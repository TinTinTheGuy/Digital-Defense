import os
import threading
import psutil
import subprocess


# Referrence on memory: https://stackoverflow.com/questions/13807498/how-can-i-read-the-memory-of-a-process-in-python-in-linux
def list_processes():
    print("\nActive Processes:")
    process_count = 0
    active_processes = []
    
    for process in psutil.process_iter():
        try:
            process_count += 1
            name = process.name()
            pid = process.pid
            active_processes.append(pid)
            print(f"{process_count}. PID: {pid} - Name: {name}")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return active_processes

def list_threads():
    print("\nActive Threads:")
    for thread in threading.enumerate():
        print(f"Thread Name: {thread.name}")

def list_modules(pid):
    try:
        process = psutil.Process(pid)
        print(f"\nModules in Process {pid}:")
        
        for module in process.memory_maps():
            print(module.path)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

def list_executables(pid):
    print(f"\nExecutables in Process {pid}:")
    proc_path = f"/proc/{pid}"
    
    for file in os.listdir(proc_path):
        if os.access(proc_path, os.X_OK):
            print(file)

def print_memory(pid):
    try:
        ps_output = subprocess.Popen(["ps", "-ux"], stdout=subprocess.PIPE)
        grep_output = subprocess.Popen(["grep", str(pid)], stdin=ps_output.stdout, stdout=subprocess.PIPE)
        ps_output.stdout.close()
        output = grep_output.communicate()[0]
        print("\nMemory Information:")
        print(output.decode('utf-8'))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

if __name__ == "__main__":
    active_processes = list_processes()
    list_threads()
    
    try:
        user_pid = int(input("\nEnter a Process ID you like to see loaded modules and executables: "))
        
        if user_pid in active_processes:
            list_modules(user_pid)
            list_executables(user_pid)
            print_memory(user_pid)
        else:
            print("Invalid Process ID, try again")
    except ProcessError:
        print("Invalid input, try again")
