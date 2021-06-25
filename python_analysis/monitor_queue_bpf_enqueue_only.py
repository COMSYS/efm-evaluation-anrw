#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# monitor_queue_bpf_enqueue_only Trace tc enqueue and dequeue operations.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: monitor_queue_bpf_enqueue_only -t type
#
# You need to name the queue type,
# if you have a stack, say of a HTB and CODEL, you can choose either
# note that choosing the bottom one causes less overhead if other
# queues are present that also use HTB but not say.. CODEL
#
#
# This uses dynamic tracing of the kernel *_dequeue() and *_encqueue() tc functions
# , and will need to be modified to match kernel changes.
#
#
# Copyright (c) 2017 Jan Rüth.
# Licensed under the Apache License, Version 2.0 (the "License")
#
from __future__ import print_function

from bcc import BPF
import ctypes as ct
import sys
from argparse import ArgumentParser
import traceback
import datetime

QDISC_FUNCS = {"HTB": ("htb_enqueue", "htb_dequeue"),
               "HFSC": ("hfsc_enqueue", "hfsc_dequeue"),
               "NETEM": ("netem_enqueue", "netem_dequeue"),
               "FQ": ("fq_enqueue", "fq_dequeue"),
               "FQ_CODEL": ("fq_codel_enqueue", "fq_codel_dequeue"),
               "CODEL": ("codel_qdisc_enqueue", "codel_qdisc_dequeue"),
               "PFIFO": ("pfifo_enqueue", "qdisc_dequeue_head"),
               "BFIFO": ("bfifo_enqueue", "qdisc_dequeue_head"),
               "PFIFO_HEAD": ("pfifo_head_enqueue", "qdisc_dequeue_head"),
               "PRIO": ("prio_enqueue", "prio_dequeue"),
               "TBF": ("tbf_enqueue", "tbf_dequeue")}


parser = ArgumentParser(description="TC Queue monitor")

parser.add_argument('--type', '-t',
                    dest="type",
                    choices=QDISC_FUNCS.keys(),
                    action="store",
                    help="Which queue type should be monitored? Possible values: HTB, HFSC, NETEM, FQ, FQ_CODEL, CODEL, PFIFO, BFIFO, PFIFO_HEAD",
                    required=True)

args = parser.parse_args()



# define BPF program
prog = """
    #include <net/sch_generic.h>
    #include <uapi/linux/gen_stats.h>
    #include <uapi/linux/if.h>

    // define output data structure in C
    struct data_t {
        u64 ts;
        u32 handle;
        u32 qlen;
        u32 qlen_qstats;
        u32 backlog;
        u32 drops;
        u32 requeues;
        u32 overlimits;
        unsigned int pkt_len_dequeued;
        char event_type[3];
        char dev_name[IFNAMSIZ];
    };
    BPF_PERF_OUTPUT(events);

    struct entry {
        struct Qdisc *qdisc;
        char dev_name[IFNAMSIZ];
    };
    BPF_HASH(currqdisc, u32, struct entry);
    BPF_HASH(currqdisc_en, u32, struct entry);


    static inline int my_strncmp(const char* a, const char* b, const ssize_t len) {
        for(int i = 0; i < len; ++i) {
            if (a[i] != b[i])
                return -1;
        }
        return 0;

    }

    struct sk_buff *dequeue_skb(struct pt_regs *ctx, struct Qdisc *q) {

        u32 pid = bpf_get_current_pid_tgid();
        struct entry e;
        e.qdisc = q;


        struct data_t data = {};
        data.handle = q->handle;
        __builtin_memcpy(data.event_type, "d\\0\\0", 3);

        __builtin_memcpy(data.dev_name, q->dev_queue->dev->name, IFNAMSIZ);

        // FILTER FUN

        __builtin_memcpy(e.dev_name, data.dev_name, IFNAMSIZ);

        currqdisc.update(&pid, &e);
        /*
        data.ts = bpf_ktime_get_ns();
        data.qlen = q->q.qlen;
        data.qlen_qstats = q->qstats.qlen;
        data.backlog = q->qstats.backlog;
        data.drops = q->qstats.drops;
        data.requeues = q->qstats.requeues;
        data.overlimits = q->qstats.overlimits;

        events.perf_submit(ctx, &data, sizeof(data));
        */


        return 0;
    }

    struct sk_buff *ret_dequeue_skb(struct pt_regs *ctx) {
        struct sk_buff * skb = (struct sk_buff *)PT_REGS_RC(ctx);

        struct entry *entryp;
        u32 tgid_pid = bpf_get_current_pid_tgid();

        entryp = currqdisc.lookup(&tgid_pid);
        if(entryp == NULL)
            return 0;

        struct Qdisc *q = entryp->qdisc;
        //bpf_probe_read(&q, sizeof(q), &entryp->qdisc);

        struct data_t data = {};

        __builtin_memcpy(data.event_type, "rd\\0", 3);

        __builtin_memcpy(data.dev_name, entryp->dev_name, IFNAMSIZ);

        data.ts = bpf_ktime_get_ns();
        bpf_probe_read(&data.handle, sizeof(data.handle), &q->handle);
        bpf_probe_read(&data.qlen, sizeof(data.qlen), &q->q.qlen);
        bpf_probe_read(&data.qlen_qstats, sizeof(data.qlen_qstats), &q->qstats.qlen);
        bpf_probe_read(&data.backlog, sizeof(data.backlog), &q->qstats.backlog);
        bpf_probe_read(&data.drops, sizeof(data.drops), &q->qstats.drops);
        bpf_probe_read(&data.requeues, sizeof(data.requeues), &q->qstats.requeues);
        bpf_probe_read(&data.overlimits, sizeof(data.overlimits), &q->qstats.overlimits);
        bpf_probe_read(&data.pkt_len_dequeued, sizeof(data.pkt_len_dequeued), &skb->len);

        events.perf_submit(ctx, &data, sizeof(data));

        currqdisc.delete(&tgid_pid);

        return 0;
    }

    struct sk_buff *enqueue_skb(struct pt_regs *ctx, struct sk_buff *skb, struct Qdisc *q, struct sk_buff **to_free) {

        u32 pid = bpf_get_current_pid_tgid();
        struct entry e;
        e.qdisc = q;


        struct data_t data = {};
        data.handle = q->handle;
        __builtin_memcpy(data.event_type, "e\\0\\0", 3);

        __builtin_memcpy(data.dev_name, q->dev_queue->dev->name, IFNAMSIZ);

        // FILTER FUN

        __builtin_memcpy(e.dev_name, data.dev_name, IFNAMSIZ);

        currqdisc_en.update(&pid, &e);
        /*
        data.ts = bpf_ktime_get_ns();
        data.qlen = q->q.qlen;
        data.qlen_qstats = q->q.qstats.qlen
        data.backlog = q->qstats.backlog;
        data.drops = q->qstats.drops;
        data.requeues = q->qstats.requeues;
        data.overlimits = q->qstats.overlimits;

        events.perf_submit(ctx, &data, sizeof(data));
        */


        return 0;
    }

    struct sk_buff *ret_enqueue_skb(struct pt_regs *ctx) {

        struct entry *entryp;
        u32 tgid_pid = bpf_get_current_pid_tgid();

        entryp = currqdisc_en.lookup(&tgid_pid);
        if(entryp == NULL)
            return 0;

        struct Qdisc *q = entryp->qdisc;
        //bpf_probe_read(&q, sizeof(q), &entryp->qdisc);

        struct data_t data = {};

        __builtin_memcpy(data.event_type, "re\\0", 3);

        __builtin_memcpy(data.dev_name, entryp->dev_name, IFNAMSIZ);

        data.ts = bpf_ktime_get_ns();
        bpf_probe_read(&data.handle, sizeof(data.handle), &q->handle);
        bpf_probe_read(&data.qlen, sizeof(data.qlen), &q->q.qlen);
        bpf_probe_read(&data.qlen_qstats, sizeof(data.qlen_qstats), &q->qstats.qlen);
        bpf_probe_read(&data.backlog, sizeof(data.backlog), &q->qstats.backlog);
        bpf_probe_read(&data.drops, sizeof(data.drops), &q->qstats.drops);
        bpf_probe_read(&data.requeues, sizeof(data.requeues), &q->qstats.requeues);
        bpf_probe_read(&data.overlimits, sizeof(data.overlimits), &q->qstats.overlimits);


        events.perf_submit(ctx, &data, sizeof(data));

        currqdisc_en.delete(&tgid_pid);

        return 0;
    }
    """

filter = ""

enqueue, dequeue = QDISC_FUNCS[args.type]
print("Hooking into {} and {}".format(enqueue, dequeue), file=sys.stderr)
print("Using filter: {}".format(filter), file=sys.stderr)

# load BPF program
b = BPF(text=prog.replace("// FILTER FUN", filter), debug=0x0)
b.attach_kprobe(event=enqueue, fn_name="enqueue_skb")
b.attach_kretprobe(event=enqueue, fn_name="ret_enqueue_skb")

# define output data structure in Python
class Data(ct.Structure):
    _fields_ = [("ts", ct.c_uint64),
                ("handle", ct.c_uint32),
                ("qlen", ct.c_uint32),
                ("qlen_qstats", ct.c_uint32),
                ("backlog", ct.c_uint32),
                ("drops", ct.c_uint32),
                ("requeues", ct.c_uint32),
                ("overlimits", ct.c_uint32),
                ("pkt_len_dequeued", ct.c_uint),
                ("event_type", ct.c_char*3),
                ("dev_name", ct.c_char*16)]

# header
format_string = "{:<14}\t{:<21}\t{:<10}\t{:<40}"
print(format_string.format("TIME(s)", "dev", "drops", "real_time"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
        start = event.ts
    time_s = float(event.ts) / 1000000000

    overall_timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    if event.dev_name == "s3-eth1":

        print(format_string.format(time_s, event.dev_name, event.drops, str(overall_timestamp)))
    
    sys.stdout.flush()

b["events"].open_perf_buffer(print_event, page_cnt=32)


try:

    while True:

        b.kprobe_poll()




except Exception as thrown_exception:

    print("Error during monitor_queue_bpf")
    print("----------------------------------------------------------------")
    print(thrown_exception)
    print(traceback.print_exc())
    pass


finally:

    b.detach_kprobe(enqueue)
    b.detach_kretprobe(enqueue)
    b.detach_kprobe(dequeue)
    b.detach_kretprobe(dequeue)