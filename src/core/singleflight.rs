use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::OnceCell;
use std::future::Future;

/// Singleflight 结构
/// 确保对于相同的 key，同一时间只有一个请求在执行
/// 其他相同的请求会等待第一个请求的结果
#[derive(Debug)]
pub struct Singleflight<K, V> 
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    inflight: DashMap<K, Arc<OnceCell<Result<V, String>>>>,
}

impl<K, V> Singleflight<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            inflight: DashMap::new(),
        }
    }

    /// 执行一个可能被合并的操作
    /// 如果已有相同 key 的请求在执行，等待其结果
    /// 否则执行 f 并与后续相同请求共享结果
    pub async fn do_work<F, Fut>(&self, key: K, f: F) -> Result<V, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, String>>,
    {
        let cell = self
            .inflight
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();

        let result_ref = cell.get_or_init(|| async move { f().await }).await;
        let result = result_ref.clone();

        // 清理 inflight map：仅去重并发窗口，完成后即移除
        self.inflight.remove(&key);

        result
    }
}

impl<K, V> Default for Singleflight<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_singleflight_deduplication() {
        let sf = Arc::new(Singleflight::<String, String>::new());
        let counter = Arc::new(AtomicU32::new(0));

        let mut handles = vec![];

        // 发起 10 个相同的并发请求
        for _ in 0..10 {
            let sf_clone = sf.clone();
            let counter_clone = counter.clone();
            
            let handle = tokio::spawn(async move {
                sf_clone.do_work("test_key".to_string(), || async {
                    // 模拟耗时操作
                    sleep(Duration::from_millis(100)).await;
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                    Ok("result".to_string())
                }).await
            });
            
            handles.push(handle);
        }

        // 等待所有请求完成
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "result");
        }

        // 验证实际只执行了一次
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
