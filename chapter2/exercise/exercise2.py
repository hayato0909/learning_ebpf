from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);
BPF_HASH(openat_counter_table);

int hello_openat(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);

    p = openat_counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    openat_counter_table.update(&uid, &counter);
    return 0;
}

int hello_write(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text=program)
syscall_open = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall_open, fn_name="hello_openat")
syscall_write = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall_write, fn_name="hello_write")

while True:
    sleep(2)
    s = "counter_table> "
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    s += "\nopenat_counter_table> "
    for k, v in b["openat_counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
