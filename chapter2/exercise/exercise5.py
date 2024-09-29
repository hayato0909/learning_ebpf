from bcc import BPF
from time import sleep

program = r"""
#include <linux/sched.h>

BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    u64 op_code = ctx->args[1];
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&op_code);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&op_code, &counter);
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"syscall_id {k.value}: {v.value}\t"
    print(s)
    print()
