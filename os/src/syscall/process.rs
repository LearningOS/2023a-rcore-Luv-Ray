//! Process management syscalls
use core::mem;

use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{translated_byte_buffer, MapPermission, VirtAddr},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, get_task_status,
        get_task_syscall_times, suspend_current_and_run_next, task_check_map, task_mmap,
        task_unmap, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");

    let us = get_time_us();
    let k_ts = &TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    } as *const TimeVal
        as *const [u8; mem::size_of::<TimeVal>() / mem::size_of::<u8>()];

    let token = current_user_token();
    let u_ts = translated_byte_buffer(token, ts as *const u8, mem::size_of::<TimeVal>());

    let mut begin = 0;
    for buffer in u_ts {
        let len = buffer.len();
        unsafe {
            buffer.copy_from_slice(&(*k_ts)[begin..len]);
            begin += len;
        }
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info!");

    let k_ti = &TaskInfo {
        status: get_task_status(),
        syscall_times: get_task_syscall_times(),
        time: get_time_ms(),
    } as *const TaskInfo
        as *const [u8; mem::size_of::<TaskInfo>() / mem::size_of::<u8>()];

    let token = current_user_token();
    let u_ti = translated_byte_buffer(token, ti as *const u8, mem::size_of::<TaskInfo>());

    let mut begin = 0;
    for buffer in u_ti {
        let len = buffer.len();
        unsafe {
            buffer.copy_from_slice(&(*k_ti)[begin..len]);
            begin += len;
        }
    }
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap!");
    let v_start = VirtAddr(start);
    let v_end = VirtAddr(start + len);

    if !v_start.aligned() {
        return -1;
    }

    let mut map_permission = MapPermission::U;
    if port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    if port & 0x1 != 0 {
        map_permission |= MapPermission::R;
    }
    if port & 0x2 != 0 {
        map_permission |= MapPermission::W;
    }
    if port & 0x4 != 0 {
        map_permission |= MapPermission::X;
    }
    if !task_check_map(v_start, v_end, false) {
        return -1;
    }

    task_mmap(v_start, v_end, map_permission);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap!");
    let v_start = VirtAddr(start);
    let v_end = VirtAddr(start + len);
    
    if !v_start.aligned() {
        return -1;
    }

    if !task_check_map(v_start, v_end, true) {
        return -1;
    }

    task_unmap(v_start, v_end);
    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
