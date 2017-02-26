// The Computer Language Benchmarks Game
// http://benchmarksgame.alioth.debian.org/
//
// contributed by the Rust Project Developers
// contributed by Matt Brubeck
// contributed by TeXitoi

extern crate libc;
extern crate crossbeam;
extern crate num_cpus;

use crossbeam::sync::chase_lev;
use crossbeam::sync::chase_lev::Steal::*;
use libc::{c_void, c_int, size_t};
use std::io::{Read, Write, ErrorKind};
use std::ptr::copy;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;

struct Tables {
    table8: [u8;1 << 8],
    table16: [u16;1 << 16]
}

impl Tables {
    fn new() -> Tables {
        let mut table8 = [0;1 << 8];
        for (i, v) in table8.iter_mut().enumerate() {
            *v = Tables::computed_cpl8(i as u8);
        }
        let mut table16 = [0;1 << 16];
        for (i, v) in table16.iter_mut().enumerate() {
            *v = (table8[i & 255] as u16) << 8 |
                 table8[i >> 8]  as u16;
        }
        Tables { table8: table8, table16: table16 }
    }

    fn computed_cpl8(c: u8) -> u8 {
        match c {
            b'A' | b'a' => b'T',
            b'C' | b'c' => b'G',
            b'G' | b'g' => b'C',
            b'T' | b't' => b'A',
            b'U' | b'u' => b'A',
            b'M' | b'm' => b'K',
            b'R' | b'r' => b'Y',
            b'W' | b'w' => b'W',
            b'S' | b's' => b'S',
            b'Y' | b'y' => b'R',
            b'K' | b'k' => b'M',
            b'V' | b'v' => b'B',
            b'H' | b'h' => b'D',
            b'D' | b'd' => b'H',
            b'B' | b'b' => b'V',
            b'N' | b'n' => b'N',
            i => i,
        }
    }

    /// Retrieves the complement for `i`.
    fn cpl8(&self, i: u8) -> u8 {
        self.table8[i as usize]
    }

    /// Retrieves the complement for `i`.
    fn cpl16(&self, i: u16) -> u16 {
        self.table16[i as usize]
    }
}

/// Finds the first position at which `b` occurs in `s`.
fn memchr(h: &[u8], n: u8) -> Option<usize> {
    let res = unsafe { libc::memchr(h.as_ptr() as *const c_void, n as c_int, h.len() as size_t) };
    if res.is_null() {
        return None
    }
    Some(res as usize - h.as_ptr() as usize)
}

/// Length of a normal line without the terminating \n.
const LINE_LEN: usize = 60;

/// Compute the reverse complement.
fn reverse_complement(seq: &mut [u8], tables: &Tables) {
    let len = seq.len() - 1;
    let seq = &mut seq[..len];// Drop the last newline
    let off = LINE_LEN - len % (LINE_LEN + 1);
    let mut i = LINE_LEN;
    while i < len {
        unsafe {
            copy(seq.as_ptr().offset((i - off) as isize),
                 seq.as_mut_ptr().offset((i - off + 1) as isize), off);
            *seq.get_unchecked_mut(i - off) = b'\n';
        }
        i += LINE_LEN + 1;
    }

    let div = len / 4;
    let rem = len % 4;
    unsafe {
        let mut left = seq.as_mut_ptr() as *mut u16;
        // This is slow if len % 2 != 0 but still faster than bytewise operations.
        let mut right = seq.as_mut_ptr().offset(len as isize - 2) as *mut u16;
        let end = left.offset(div as isize);
        while left != end {
            let tmp = tables.cpl16(*left);
            *left = tables.cpl16(*right);
            *right = tmp;
            left = left.offset(1);
            right = right.offset(-1);
        }

        let end = end as *mut u8;
        match rem {
            1 => *end = tables.cpl8(*end),
            2 => {
                let tmp = tables.cpl8(*end);
                *end = tables.cpl8(*end.offset(1));
                *end.offset(1) = tmp;
            },
            3 => {
                *end.offset(1) = tables.cpl8(*end.offset(1));
                let tmp = tables.cpl8(*end);
                *end = tables.cpl8(*end.offset(2));
                *end.offset(2) = tmp;
            },
            _ => { },
        }
    }
}

fn file_size(f: &mut File) -> std::io::Result<usize> {
    Ok(f.metadata()?.len() as usize)
}

/// Combine two adjacent slices into a single slice
fn mend<'a, T>(a: &'a mut [T], b: &'a mut [T]) -> &'a mut [T] {
    unsafe {
        assert!(a.as_ptr().offset(a.len() as isize) == b.as_ptr());
        std::slice::from_raw_parts_mut(a.as_mut_ptr(), a.len() + b.len())
    }
}

fn main() {
    let mut stdin = unsafe { File::from_raw_fd(0) };
    let size = file_size(&mut stdin).unwrap_or(1024 * 1024);

    let mut buf = vec![0; size];
    let read_finished = &AtomicBool::new(false);
    let tables = &Tables::new();

    crossbeam::scope(|scope| {
        let (mut data, mut buf) = buf.split_at_mut(0);
        // The reader thread reads from stdin and sends each chunk of input to the dispatch thread.
        let (reader_tx, reader_rx) = channel();
        scope.spawn(move || {
            while !buf.is_empty() {
                match stdin.read(buf) {
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => panic!("io error: {}", e),
                    Ok(0) => break,
                    Ok(n) => {
                        let (new_data, tail) = {buf}.split_at_mut(n);
                        buf = tail;
                        reader_tx.send(new_data).expect("reader_tx failed");
                    }
                }
            }
        });

        // The worker threads process each sequence in the work queue.
        let (mut work_queue, work_stealer) = chase_lev::deque();
        for _ in 0..num_cpus::get() - 1 {
            let work_stealer = work_stealer.clone();
            scope.spawn(move || {
                loop {
                    match work_stealer.steal() {
                        Data(seq) => reverse_complement(seq, tables),
                        Empty if read_finished.load(Ordering::SeqCst) => break,
                        Empty | Abort => continue,
                    }
                }
            });
        }

        // The main thread receives inpupt from the reader thread, splits it into sequences,
        // and puts the sequences into the work queue.
        //scope.spawn(move || {
            let mut bytes_read = 0;
            while let Ok(new_data) = reader_rx.recv() {
                bytes_read += new_data.len();
                let old_data = data;
                data = mend(old_data, new_data);

                while !data.is_empty() {
                    data = match memchr(data, b'\n') {
                        Some(i) => {data}.split_at_mut(i + 1).1,
                        None => continue
                    };
                    let (seq, tail) = match memchr(data, b'>') {
                        Some(i) => {data}.split_at_mut(i),
                        None if bytes_read == size => (data, &mut [][..]),
                        None => continue // TODO: final chunk
                    };
                    work_queue.push(seq);
                    data = tail;
                }
            }
            read_finished.store(true, Ordering::SeqCst);
        //});
    });

    let stdout = std::io::stdout();
    stdout.lock().write_all(&buf).unwrap();
}
