use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use weak_map::{StrongMap, WeakMap};

use crate::{Pid, ProcessGroup, Session, Thread};

pub(crate) struct ThreadGroup {
    pub(crate) threads: WeakMap<Pid, Weak<Thread>>,
    pub(crate) exit_code: i32,
    pub(crate) group_exited: bool,
}

impl Default for ThreadGroup {
    fn default() -> Self {
        Self {
            threads: WeakMap::new(),
            exit_code: 0,
            group_exited: false,
        }
    }
}

pub trait ProcessExt: Send + Sync {
    fn base(&self) -> &Process;
    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
    fn set_group(self: Arc<Self>, group: &Arc<ProcessGroup>);
    fn new_thread(self: Arc<Self>, tid: Pid) -> Arc<Thread>;
    fn pid(&self) -> Pid {
        self.base().pid
    }
    fn group(&self) -> Arc<ProcessGroup> {
        self.base().group.lock().clone()
    }
    fn parent(&self) -> Option<Arc<dyn ProcessExt>> {
        self.base().parent.lock().as_ref().and_then(|p| p.upgrade())
    }
    fn children(&self) -> Vec<Arc<dyn ProcessExt>> {
        self.base().children.lock().values().cloned().collect()
    }
    fn exit(&self) {
        self.base().exit();
    }
    fn free(&self) {
        self.base().free();
    }
}

/// A process.
pub struct Process {
    pid: Pid,
    is_zombie: AtomicBool,
    pub(crate) tg: SpinNoIrq<ThreadGroup>,

    // TODO: child subreaper
    children: SpinNoIrq<StrongMap<Pid, Arc<dyn ProcessExt>>>,
    parent: SpinNoIrq<Option<Weak<dyn ProcessExt>>>,

    group: SpinNoIrq<Arc<ProcessGroup>>,
}

impl ProcessExt for Process {
    fn base(&self) -> &Process {
        self
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn set_group(self: Arc<Self>, group: &Arc<ProcessGroup>) {
        let mut self_group = self.group.lock();

        self_group.processes.lock().remove(&self.pid);

        group
            .processes
            .lock()
            .insert(self.pid, &(self.clone() as Arc<dyn ProcessExt>));

        *self_group = group.clone();
    }

    fn new_thread(self: Arc<Self>, tid: Pid) -> Arc<Thread> {
        let thread = Arc::new(Thread {
            tid,
            process: self.clone(),
        });
        self.tg.lock().threads.insert(tid, &thread);
        thread
    }
}

impl Process {
    /// The [`Process`] ID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Returns `true` if the [`Process`] is the init process.
    ///
    /// This is a convenience method for checking if the [`Process`]
    /// [`Arc::ptr_eq`]s with the init process, which is cheaper than
    /// calling [`init_proc`] or testing if [`Process::parent`] is `None`.
    pub fn is_init(self: &Arc<Self>) -> bool {
        Arc::ptr_eq(self, INIT_PROC.get().unwrap())
    }
}

/// Parent & children
impl Process {
    /// The parent [`Process`].
    pub fn parent(&self) -> Option<Arc<dyn ProcessExt>> {
        self.parent.lock().as_ref().and_then(|p| p.upgrade())
    }

    /// The child [`Process`]es.
    pub fn children(&self) -> Vec<Arc<dyn ProcessExt>> {
        self.children.lock().values().cloned().collect()
    }
}

/// [`ProcessGroup`] & [`Session`]
impl Process {
    /// The [`ProcessGroup`] that the [`Process`] belongs to.
    pub fn group(&self) -> Arc<ProcessGroup> {
        self.group.lock().clone()
    }

    /// Creates a new [`Session`] and new [`ProcessGroup`] and moves the
    /// [`Process`] to it.
    ///
    /// If the [`Process`] is already a session leader, this method does
    /// nothing and returns `None`.
    ///
    /// Otherwise, it returns the new [`Session`] and [`ProcessGroup`].
    ///
    /// The caller has to ensure that the new [`ProcessGroup`] does not conflict
    /// with any existing [`ProcessGroup`]. Thus, the [`Process`] must not
    /// be a [`ProcessGroup`] leader.
    ///
    /// Checking [`Session`] conflicts is unnecessary.
    pub fn create_session(self: Arc<Self>) -> Option<(Arc<Session>, Arc<ProcessGroup>)> {
        if self.group.lock().session.sid() == self.pid {
            return None;
        }

        let new_session = Session::new(self.pid);
        let new_group = ProcessGroup::new(self.pid, &new_session);
        self.set_group(&new_group);

        Some((new_session, new_group))
    }

    /// Creates a new [`ProcessGroup`] and moves the [`Process`] to it.
    ///
    /// If the [`Process`] is already a group leader, this method does nothing
    /// and returns `None`.
    ///
    /// Otherwise, it returns the new [`ProcessGroup`].
    ///
    /// The caller has to ensure that the new [`ProcessGroup`] does not conflict
    /// with any existing [`ProcessGroup`].
    pub fn create_group(self: Arc<Self>) -> Option<Arc<ProcessGroup>> {
        if self.group.lock().pgid() == self.pid {
            return None;
        }

        let new_group = ProcessGroup::new(self.pid, &self.group.lock().session);
        self.set_group(&new_group);

        Some(new_group)
    }

    /// Moves the [`Process`] to a specified [`ProcessGroup`].
    ///
    /// Returns `true` if the move succeeded. The move failed if the
    /// [`ProcessGroup`] is not in the same [`Session`] as the [`Process`].
    ///
    /// If the [`Process`] is already in the specified [`ProcessGroup`], this
    /// method does nothing and returns `true`.
    pub fn move_to_group(self: Arc<Self>, group: &Arc<ProcessGroup>) -> bool {
        if Arc::ptr_eq(&self.group.lock(), group) {
            return true;
        }

        if !Arc::ptr_eq(&self.group.lock().session, &group.session) {
            return false;
        }

        self.set_group(group);
        true
    }
}

/// Threads
impl Process {
    /// The [`Thread`]s in this [`Process`].
    pub fn threads(&self) -> Vec<Arc<Thread>> {
        self.tg.lock().threads.values().collect()
    }

    /// Returns `true` if the [`Process`] is group exited.
    pub fn is_group_exited(&self) -> bool {
        self.tg.lock().group_exited
    }

    /// Marks the [`Process`] as group exited.
    pub fn group_exit(&self) {
        self.tg.lock().group_exited = true;
    }

    /// The exit code of the [`Process`].
    pub fn exit_code(&self) -> i32 {
        self.tg.lock().exit_code
    }
}

/// Status & exit
impl Process {
    /// Returns `true` if the [`Process`] is a zombie process.
    pub fn is_zombie(&self) -> bool {
        self.is_zombie.load(Ordering::Acquire)
    }

    /// Terminates the [`Process`], marking it as a zombie process.
    ///
    /// Child processes are inherited by the init process or by the nearest
    /// subreaper process.
    ///
    /// This method panics if the [`Process`] is the init process.
    pub fn exit(self: &Arc<Self>) {
        if self.is_init() {
            panic!("init process cannot exit");
        }

        // TODO: child subreaper
        let reaper = INIT_PROC.get().unwrap();

        let mut children = self.children.lock(); // Acquire the lock first
        self.is_zombie.store(true, Ordering::Release);

        let mut reaper_children = reaper.children.lock();
        let reaper = Arc::downgrade(reaper);

        for (pid, child) in core::mem::take(&mut *children) {
            *child.base().parent.lock() = Some(reaper.clone());
            reaper_children.insert(pid, child);
        }
    }

    /// Frees a zombie [`Process`]. Removes it from the parent.
    ///
    /// This method panics if the [`Process`] is not a zombie.
    pub fn free(&self) {
        assert!(self.is_zombie(), "only zombie process can be freed");

        if let Some(parent) = self.parent() {
            parent.base().children.lock().remove(&self.pid);
        }
    }
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("Process");
        builder.field("pid", &self.pid);

        let tg = self.tg.lock();
        if tg.group_exited {
            builder.field("group_exited", &tg.group_exited);
        }
        if self.is_zombie() {
            builder.field("exit_code", &tg.exit_code);
        }

        if let Some(parent) = self.parent() {
            builder.field("parent", &parent.pid());
        }
        builder.field("group", &self.group());
        builder.finish()
    }
}

/// Builder
impl Process {
    fn new(pid: Pid, parent: Option<Arc<dyn ProcessExt>>) -> Arc<Process> {
        let group = parent.as_ref().map_or_else(
            || {
                let session = Session::new(pid);
                ProcessGroup::new(pid, &session)
            },
            |p| p.group(),
        );

        let process = Arc::new(Process {
            pid,
            is_zombie: AtomicBool::new(false),
            tg: SpinNoIrq::new(ThreadGroup::default()),
            children: SpinNoIrq::new(StrongMap::new()),
            parent: SpinNoIrq::new(
                parent
                    .as_ref()
                    .map(|p| Arc::downgrade(p) as Weak<dyn ProcessExt>),
            ),
            group: SpinNoIrq::new(group.clone()),
        });

        group
            .processes
            .lock()
            .insert(pid, &(process.clone() as Arc<dyn ProcessExt>));

        if let Some(parent) = parent {
            parent
                .base()
                .children
                .lock()
                .insert(pid, process.clone() as Arc<dyn ProcessExt>);
        } else {
            INIT_PROC.init_once(process.clone());
        }

        process
    }

    /// Creates a init [`Process`].
    ///
    /// This function can be called multiple times, but
    /// [`ProcessBuilder::build`] on the the result must be called only once.
    pub fn new_init(pid: Pid) -> Arc<Process> {
        Self::new(pid, None)
    }

    /// Creates a child [`Process`].
    pub fn fork(self: &Arc<Process>, pid: Pid) -> Arc<Process> {
        Self::new(pid, Some(self.clone() as Arc<dyn ProcessExt>))
    }
}

static INIT_PROC: LazyInit<Arc<Process>> = LazyInit::new();

/// Gets the init process.
///
/// This function panics if the init process has not been initialized yet.
pub fn init_proc() -> Arc<Process> {
    INIT_PROC.get().unwrap().clone()
}
