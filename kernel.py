import ctypes
import functools
import logging
import time
import sys
from threading import Lock

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('kernel.log'),
                              logging.StreamHandler()])

ERROR_PROCESS_MANAGEMENT = "0xe1_kernel"
ERROR_MEMORY_EXHAUSTION = "0xe2_kernel"
MAX_PROCESSES = 1000

kernel_lock = Lock()

class Process:
    def __init__(self, pid, name, memory_id, priority=0):
        self.pid = pid
        self.name = name
        self.memory_id = memory_id
        self.priority = priority

class MemoryManager:
    def __init__(self):
        self.allocated_memory = {}

    def allocate_memory(self, size):
        mem = ctypes.create_string_buffer(size)
        self.allocated_memory[id(mem)] = (mem, size)
        return id(mem)

    def deallocate_memory(self, mem_id):
        if mem_id in self.allocated_memory:
            del self.allocated_memory[mem_id]
            logging.debug(f"Memory deallocated for ID: {mem_id}")
        else:
            logging.warning(f"Attempt to free unallocated memory ID: {mem_id}")

class Kernel:
    def __init__(self):
        self.processes = []
        self.memory_manager = MemoryManager()
        self.next_pid = 1

    def process_exists(self, pid):
        return any(process.pid == pid for process in self.processes)

    def create_process(self, name, priority=0, memory_size=1024):
        with kernel_lock:
            if len(self.processes) >= MAX_PROCESSES:
                logging.error("Memory exhaustion: Maximum number of processes reached.")
                self.kernel_panic("Memory exhaustion", ERROR_MEMORY_EXHAUSTION)

            pid = self.next_pid
            self.next_pid += 1
            process_memory_id = self.memory_manager.allocate_memory(memory_size)
            process = Process(pid, name, process_memory_id, priority)
            self.processes.append(process)
            logging.info(f"Process created - PID: {pid}, Name: {name}, Memory: {memory_size} bytes.")
            return pid

    def kill_process(self, pid):
        with kernel_lock:
            for i, process in enumerate(self.processes):
                if process.pid == pid:
                    self.memory_manager.deallocate_memory(process.memory_id)
                    logging.info(f"Process terminated - PID: {pid}, Name: {process.name}")
                    del self.processes[i]
                    return
            logging.warning(f"Process with PID {pid} not found.")

    def kernel_panic(self, message, error_code):
        logging.critical(f"KERNEL PANIC: {message}, Error Code: {error_code}. Restart required.")
        sys.exit(1)

kernel = Kernel()

def process_management(priority=1):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            pid = None
            try:
                pid = kernel.create_process(func.__name__, priority=priority)
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                logging.error(f"Kernel error occurred: {e}")
                kernel.kernel_panic("Process management error", ERROR_PROCESS_MANAGEMENT)
            finally:
                if pid:
                    kernel.kill_process(pid)
        return wrapper
    return decorator

@process_management(priority=2)
def demo_process():
    logging.info("Demo process running...")
    time.sleep(2)
    logging.info("Demo process completed.")

def kernel_main():
    logging.info("Kernel main started.")
    try:
        while True:
            logging.debug("Kernel is running")
            demo_process()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Kernel shutdown requested by user.")
    except Exception as e:
        logging.error(f"Unexpected kernel main loop error: {e}")
        kernel.kernel_panic("Fatal error in main loop", "0xe3_kernel")

if __name__ == "__main__":
    kernel_main()
