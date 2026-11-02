use crate::models::EdrEventType;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Condvar, Mutex};
use std::time::Instant;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePriority {
    Critical = 3,
    High = 2,
    Normal = 1,
    Low = 0,
}

#[derive(Debug, Clone)]
pub struct QueueItem {
    pub sequence_id: u64,
    pub priority: QueuePriority,
    pub path: PathBuf,
    pub event_type: EdrEventType,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub comm: Option<String>,
    pub enqueued_at: Instant,
}

impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence_id == other.sequence_id
    }
}

impl Eq for QueueItem {}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Mayor prioridad primero. En empate, menor sequence_id (FIFO)
        match (self.priority as u8).cmp(&(other.priority as u8)) {
            Ordering::Equal => other.sequence_id.cmp(&self.sequence_id),
            ord => ord,
        }
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Cola asíncrona priorizada con control de saturación y prevención de desbordamiento (Backpressure)
pub struct EdrEventQueue {
    heap: Mutex<BinaryHeap<QueueItem>>,
    condvar: Condvar,
    seq_counter: AtomicU64,
    max_capacity: usize,
    dropped_count: AtomicUsize,
    total_enqueued: AtomicU64,
    total_processed: AtomicU64,
}

impl EdrEventQueue {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::with_capacity(max_capacity.min(4096))),
            condvar: Condvar::new(),
            seq_counter: AtomicU64::new(1),
            max_capacity,
            dropped_count: AtomicUsize::new(0),
            total_enqueued: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
        }
    }

    /// Encola un nuevo evento según su nivel de urgencia
    pub fn enqueue(
        &self,
        priority: QueuePriority,
        path: PathBuf,
        event_type: EdrEventType,
        pid: Option<u32>,
        ppid: Option<u32>,
        comm: Option<String>,
    ) -> bool {
        let seq = self.seq_counter.fetch_add(1, AtomicOrdering::SeqCst);
        let item = QueueItem {
            sequence_id: seq,
            priority,
            path,
            event_type,
            pid,
            ppid,
            comm,
            enqueued_at: Instant::now(),
        };

        let mut queue = match self.heap.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        if queue.len() >= self.max_capacity {
            // Control de saturación: si el elemento entrante no es crítico, descartarlo
            if priority != QueuePriority::Critical {
                self.dropped_count.fetch_add(1, AtomicOrdering::Relaxed);
                warn!(
                    "Cola EDR saturada ({} elementos). Descartado evento de prioridad {:?} en {}",
                    queue.len(),
                    priority,
                    item.path.display()
                );
                return false;
            }
        }

        queue.push(item);
        self.total_enqueued.fetch_add(1, AtomicOrdering::Relaxed);
        self.condvar.notify_one();
        true
    }

    /// Extrae el siguiente evento de mayor prioridad, bloqueando con timeout
    pub fn pop_timeout(&self, timeout: std::time::Duration) -> Option<QueueItem> {
        let mut queue = self.heap.lock().ok()?;

        while queue.is_empty() {
            let (new_guard, wait_res) = self.condvar.wait_timeout(queue, timeout).ok()?;
            queue = new_guard;
            if wait_res.timed_out() && queue.is_empty() {
                return None;
            }
        }

        let item = queue.pop();
        if item.is_some() {
            self.total_processed.fetch_add(1, AtomicOrdering::Relaxed);
        }
        item
    }

    /// Retorna la cantidad de eventos en espera
    pub fn len(&self) -> usize {
        self.heap.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_dropped_count(&self) -> usize {
        self.dropped_count.load(AtomicOrdering::Relaxed)
    }

    pub fn get_total_enqueued(&self) -> u64 {
        self.total_enqueued.load(AtomicOrdering::Relaxed)
    }

    pub fn get_total_processed(&self) -> u64 {
        self.total_processed.load(AtomicOrdering::Relaxed)
    }
}
