---
title: "探索 eBPF 源码之旅"
date: 2023-03-11T01:59:22+08:00
draft: false
keywords: 
- eBPF
- Linux
- 内核
- XDP
tags: [eBPF, Linux, 内核, XDP]
categories: [eBPF]
description: 这篇文章是关于 Linux 内核中的 eBPF 源代码的介绍。经过一系列的跟踪和解释，展示了如何使用 eBPF 进行数据包过滤和转发。文章中还介绍了 eBPF 的一些基本概念和工具，如 eBPF 指令集、clang、bpftool 等。同时，文章还介绍了 eBPF 程序在内核中的分配和更新，以及如何使用 eBPF 程序进行 XDP 和 TC 等网络操作。
---

## 0x00 序

我是从 [lb-from-scratch](https://github.com/lizrice/lb-from-scratch) 开始学习 eBPF，这个 demo 是 Liz Rice 在 eBPF Summit 2021 [^1]上的演讲使用的。这个 demo 用于展示如何使用 eBPF 来实现一个简单的负载均衡器。我在这里记录了我在探索源码过程中的一些记录。

## 0x01 顺藤摸瓜

### 编译

这个 demo 用到了 `bpftool` 和 `libbpf` 两个项目。

执行 `make` 来加载 `xdp_lb_kern.c` 这个 eBPF 程序时，实际对应的指令是：

```Makefile
xdp: $(BPF_OBJ)
    bpftool net detach xdpgeneric dev eth0
    rm -f /sys/fs/bpf/$(TARGET)
    bpftool --debug prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
    bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(TARGET) dev eth0
```

`BPF_OBJ` 是 `xdp_lb_kern.o`，即 `xdp_lb_kern.c` 编译之后的 ELF 二进制。

在 `xdp: $(BPF_OBJ)` 这行 Makefile 声明中，xdp 是默认目标 targets，$(BPF_OBJ) 是目标所依赖的文件（或依赖目标）prerequisites。

### ELF 对象

`xdp_lb_kern.o` 是 clang 编译出来的二进制对象，可以在编译时加上 -g 参数，例如：

```makefile
$(BPF_OBJ): %.o: %.c
    clang -S \
        -target bpf \
        -g \
        -D __BPF_TRACING__ \
        -Ilibbpf/src\
        -Wall \
        -Wno-unused-value \
        -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
        -Werror \
        -O2 -emit-llvm -c -o ${@:.o=.ll} $<
    llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
```

再通过 `llvm-objdump -S xdp_lb_kern.o` 来查看带有调试信息的对应文件[^2]，可以看到：

```asm
file xdp_lb_kern.o
xdp_lb_kern.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped

readelf -a xdp_lb_kern.o 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  ...
```

### 加载 eBPF 用户态程序

```bash
bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
```

bpftool prog[^3] load 命令用于加载 eBPF 程序，可以通过 `bpftool prog load --help` 查看帮助信息。

bpftool prog load 的代码[^4]追踪：

```c
// tools/bpf/bpftool/prog.c
static const struct cmd cmds[] = {
    { "load",   do_load },
};
```

```c
// tools/bpf/bpftool/prog.c
static int do_load(int argc, char **argv)
{
    if (use_loader)
        return do_loader(argc, argv);
    return load_with_options(argc, argv, true);
}
```

`use_loader` 来自于命令行中的 `-L, --use-loader` 参数，将程序作为 `loader` 程序加载。这对于调试生成这些程序非常有用。

```c
// tools/bpf/bpftool/prog.c
static int load_with_options(int argc, char **argv, bool first_prog_only)
{
    ...
    // 从命令行中解析参数 'type', 'map' or 'dev' 等参数
    while (argc) {
        ...
    }

    ...
    // verifier_logs 来源于命令行中的 '-d, --debug' 参数
    if (verifier_logs)

    // 打开编译后的 eBPF 二进制对象
    obj = bpf_object__open_file(file, &open_opts);
    ...
    bpf_object__for_each_program(pos, obj) {
        ...
        // 处理 section， type 等

        // ifindex 为 0, 因为 prog load 的时候并没有指定加载到哪一个网卡上
        bpf_program__set_ifindex(pos, ifindex);
        // prog_type 是 6, 标识 enum bpf_prog_type 中的 BPF_PROG_TYPE_XDP
        bpf_program__set_type(pos, prog_type);
        // expected_attach_type 是 37, 标识 enum bpf_attach_type 中的 BPF_XDP
        bpf_program__set_expected_attach_type(pos, expected_attach_type);
    }

    // 对 eBPF map 进行处理
    ...

    // 加载 eBPF 程序
    err = bpf_object__load(obj);

    // pinfile 是 /sys/fs/bpf/xx
    // mount_bpffs_for_pin 函数 接受 name 参数，参数指向用于挂载 BPF 文件系统以固定对象的名称。函数将在 /sys/fs/bpf 目录中创建一个新目录，并将其挂载到传递给函数的名称所在的目录。如果此目录已经是BPF文件系统，则不需要执行任何操作，否则函数将调用 is_bpffs 函数进行检查。
    err = mount_bpffs_for_pin(pinfile);

    ...
    // 从 eBPF 二进制对象中加载 prog
    // 将 prog 通过 syscall 执行 BPF_OBJ_PIN 命令，将 prog pin 到 /sys/fs/bpf/xx
    // 关闭二进制文件
}
```

`ifindex` 就是网卡的索引，可以通过 `ip link list` 来查看网卡的索引以及其他信息。`prog_type` 是 eBPF 程序的类型，`expected_attach_type` 是 eBPF 程序的附加类型。

### attach eBPF 程序到网卡

```bash
bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(TARGET) dev eth0
```

bpftool net attach 命令用于将 eBPF 程序附加到网卡上，可以通过 `bpftool net attach --help` 查看帮助信息。

bpftool net 代码追踪

```c
// tools/bpf/bpftool/net.c
static const struct cmd cmds[] = {
    { "attach", do_attach },
};
```

```c
// tools/bpf/bpftool/net.c
static int do_attach(int argc, char **argv)
{
    ...
    // 解析 attach_type, 是 'xdpgeneric'
    attach_type = parse_attach_type(*argv);

    ...
    // progfd 为 load 的 eBPF 程序返回的 fd
    progfd = prog_parse_fd(&argc, &argv);

    ...
    // ifindex 为网卡的标识
    ifindex = net_parse_dev(&argc, &argv);

    ...
    // 执行 attach
    if (is_prefix("xdp", attach_type_strings[attach_type]))
        err = do_attach_detach_xdp(progfd, attach_type, ifindex,
                   overwrite);
```

XDP 总共支持三种工作模式[^5]， xdpgeneric 表示 generic XDP（通用 XDP）[^6]，用于给那些还没有原生支持 XDP 的驱动进行试验性测试。

`do_attach_detach_xdp` 函数代码追踪

```c
// tools/bpf/bpftool/net.c
static int do_attach_detach_xdp(int progfd, enum net_attach_type attach_type,
                int ifindex, bool overwrite)
{
    // 判断 attach type 类型
    if (attach_type == NET_ATTACH_TYPE_XDP_GENERIC)
        flags |= XDP_FLAGS_SKB_MODE;
    ...

    return bpf_xdp_attach(ifindex, progfd, flags, NULL);
}
```

`bpf_xdp_attach` 函数代码追踪

```c
// libbpf/src/netlink.c
int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts *opts)
{
    // 查找 old_prog_fd，即旧的 BPF 程序文件描述符，如果存在则替换，不存在则直接加载
    err = __bpf_set_link_xdp_fd_replace(ifindex, prog_fd, old_prog_fd, flags);
}
```

`__bpf_set_link_xdp_fd_replace` 函数代码追踪

```c
static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd,
                    __u32 flags)
{
    struct nlattr *nla;
    int ret;
    struct libbpf_nla_req req;

    // 初始化 netlink 请求
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags    = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type     = RTM_SETLINK;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index  = ifindex;

    // 构建 netlink 请求，设置请求类型为 IFLA_XDP
    nla = nlattr_begin_nested(&req, IFLA_XDP);
    if (!nla)
        return -EMSGSIZE;

    // nlattr_add 函数用于封装 netlink 的请求
    ret = nlattr_add(&req, IFLA_XDP_FD, &fd, sizeof(fd));
    if (ret < 0)
        return ret;
    if (flags) {
        ret = nlattr_add(&req, IFLA_XDP_FLAGS, &flags, sizeof(flags));
        if (ret < 0)
            return ret;
    }
    if (flags & XDP_FLAGS_REPLACE) {
        ret = nlattr_add(&req, IFLA_XDP_EXPECTED_FD, &old_fd,
                    sizeof(old_fd));
        if (ret < 0)
            return ret;
    }
    nlattr_end_nested(&req, nla);

    return libbpf_netlink_send_recv(&req, NULL, NULL, NULL);
}
```

### linux 内核中的 eBPF 程序

使用 netlink 与内核进行通信。netlink 是 linux 提供的用于内核和用户态进程之间的通信方式。

这个 netlink 请求的类型是 IFLA_XDP，子类型是 IFLA_XDP_FD，表示要关联 bpf_prog[^7]。在内核中，处理该该请求的代码

```c
// net/core/rtnetlink.c
static int do_setlink(const struct sk_buff *skb,
              struct net_device *dev, struct ifinfomsg *ifm,
              struct netlink_ext_ack *extack,
              struct nlattr **tb, int status)
{
    ...
    if (tb[IFLA_XDP]) {
        ...
        // 处理 IFLA_XDP_FD
        if (xdp[IFLA_XDP_FD]) {
            ...
            // dev_change_xdp_fd 意为为 dev 关联一个 XDP 程序的 fd， 它使用网卡设备驱动程序的 do_bpf 方法，进行 XDP 程序的安装
            err = dev_change_xdp_fd(dev, extack,
                        nla_get_s32(xdp[IFLA_XDP_FD]),
                        expected_fd,
                        xdp_flags);
            ...            
        }
    }
```

`dev_change_xdp_fd` 函数代码追踪

```c
// net/core/dev.c
int dev_change_xdp_fd(struct net_device *dev, struct netlink_ext_ack *extack,
            int fd, int expected_fd, u32 flags)
{
    ...
    // 获取BPF程序实例
        new_prog = bpf_prog_get_type_dev(fd, BPF_PROG_TYPE_XDP,
                         mode != XDP_MODE_SKB);

    ...
    // 为网卡设备安装 XDP 程序
    err = dev_xdp_attach(dev, extack, NULL, new_prog, old_prog, flags);

}
```

`dev_xdp_attach` 函数代码追踪

```c
// net/core/dev.c
static int dev_xdp_attach(struct net_device *dev, struct netlink_ext_ack *extack,
              struct bpf_xdp_link *link, struct bpf_prog *new_prog,
              struct bpf_prog *old_prog, u32 flags)
{
    ...
    netdev_for_each_upper_dev_rcu(dev, upper, iter) {
    ...
    }
```

`netdev_for_each_upper_dev_rcu` 函数代码追踪

```c
// include/linux/netdevice.h
#define netdev_for_each_upper_dev_rcu(dev, updev, iter) \
    for (iter = &(dev)->adj_list.upper, \
         updev = netdev_upper_get_next_dev_rcu(dev, &(iter)); \
         updev; \
         updev = netdev_upper_get_next_dev_rcu(dev, &(iter)))
```

`netdev_upper_get_next_dev_rcu` 函数代码追踪

```c
// net/core/dev.c
struct net_device *netdev_upper_get_next_dev_rcu(struct net_device *dev,
                         struct list_head **iter)
{
    struct netdev_adjacent *upper;

    // 检查是否在rcu_read_lock保护内或 rtnl_lock 中嵌套了 rcu_read_lock保护
    WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_rtnl_is_held());

    upper = list_entry_rcu((*iter)->next, struct netdev_adjacent, list);

    // 检查返回的相邻设备是否等于本设备. 如果是，则说明达到链表的末尾，返回NULL。
    if (&upper->list == &dev->adj_list.upper)
        return NULL;

    // 更新迭代器并返回找到的下一个相邻设备的 net_device 对象指针    
    *iter = &upper->list;

    return upper->dev;
}
```

`list_entry_rcu` 是内核中定义的函数，根据指向结构体 type 中成员 member 的指针 ptr，返回指向该结构体的指针。

```c
#define list_entry_rcu(ptr, type, member)
```

在 `netdev_upper_get_next_dev_rcu` 这个宏中，`iter` 是一个指向 `dev->adj_list.upper` 的指针，`dev->adj_list.upper` 是一个双向链表。在 `netdev_upper_get_next_dev_rcu` 中，通过 `list_entry_rcu` 来遍历 `dev->adj_list.upper` 这个链表，获取链表中的每一个元素，即获取关联在给定设备的下一个设备。

回到 `dev_xdp_attach` 函数

```c
    // 获取当前的 XDP 程序，会有 prog 与 link 两种情况的处理
    cur_prog = dev_xdp_prog(dev, mode);
    ...
    
    if (new_prog != cur_prog) {
        bpf_op = dev_xdp_bpf_op(dev, mode);
```

`dev_xdp_bpf_op` 是寻找网卡的 ndo_bpf 实现

```c
// net/core/dev.c
static bpf_op_t dev_xdp_bpf_op(struct net_device *dev, enum bpf_xdp_mode mode)
{
    switch (mode) {
    case XDP_MODE_SKB:
        return generic_xdp_install;
    case XDP_MODE_DRV:
    case XDP_MODE_HW:
        return dev->netdev_ops->ndo_bpf;
    default:
        return NULL;
    }
}
```

这里我比较想知道 mode 是什么，于是用 retsnoop 进行跟踪，从 `dev_xdp_prog` 的代码

```c
// net/core/dev.c
static struct bpf_prog *dev_xdp_prog(struct net_device *dev,
                     enum bpf_xdp_mode mode)
{
    struct bpf_xdp_link *link = dev_xdp_link(dev, mode);

    if (link)
        return link->link.prog;
    return dev->xdp_state[mode].prog;
}
```

可知，dev->xdp_state 是一个数组，数组的下标是 `enum bpf_xdp_mode`，这个枚举类型的定义如下

```c
// include/linux/netdevice.h
enum bpf_xdp_mode {
    XDP_MODE_SKB = 0,
    XDP_MODE_DRV = 1,
    XDP_MODE_HW = 2,
    __MAX_XDP_MODE
};
```

使用 drgn[^8] 进行调试

```shell
$sudo drgn
...

list(netdev_get_by_name(prog, "enp0s5").xdp_state)[0].prog.aux.name
(char [16])"xdp_anti_ddos"
```

`enp0s5`是我的网卡名，`xdp_anti_ddos`是我挂载的程序名，`xdp_state[mode]`即`xdp_state[XDP_MODE_SKB]`下挂载的 eBPF 程序，可以看到，这个程序是挂载在`XDP_MODE_SKB` 模式下的。

其实从根源来说，`mode` 来源于 `do_attach_detach_xdp` 时

```c
    if (attach_type == NET_ATTACH_TYPE_XDP_GENERIC)
            flags |= XDP_FLAGS_SKB_MODE;
```

在 `__bpf_set_link_xdp_fd_replace` 中组成 netlink 消息的一部分

```c
    if (flags) {
        ret = nlattr_add(&req, IFLA_XDP_FLAGS, &flags, sizeof(flags));
```

接受消息后，在 `dev_xdp_mode` 中转换成 `XDP_MODE_SKB`

```c
static enum bpf_xdp_mode dev_xdp_mode(struct net_device *dev, u32 flags)
{
    if (flags & XDP_FLAGS_SKB_MODE)
        return XDP_MODE_SKB;
}
```

最后在 `dev_xdp_prog` 中放在了 `dev->xdp_state` 中

```c
static struct bpf_prog *dev_xdp_prog(struct net_device *dev,
                     enum bpf_xdp_mode mode)
{
    ...
    return dev->xdp_state[mode].prog;
}
```

再次回到 `dev_xdp_attach`

```c
    /* don't call drivers if the effective program didn't change */
    if (new_prog != cur_prog) {
        bpf_op = dev_xdp_bpf_op(dev, mode);
        if (!bpf_op) {
            NL_SET_ERR_MSG(extack, "Underlying driver does not support XDP in native mode");
            return -EOPNOTSUPP;
        }

        err = dev_xdp_install(dev, mode, bpf_op, extack, flags, new_prog);
        if (err)
            return err;
    }
```

这里是真正执行安装的地方，`dev_xdp_install` 会调用 `ndo_bpf`，这个函数是在 `ndo_bpf` 中注册的

```c
static int dev_xdp_install(struct net_device *dev, enum bpf_xdp_mode mode,
               bpf_op_t bpf_op, struct netlink_ext_ack *extack,
               u32 flags, struct bpf_prog *prog)
{
    // 为 XDP 构建的 meta 结构体，用于在不同模式下设置 XDP 程序、传递相关信息和标记等操作
    // 处理 prog 的引用计数
    ...
    if (mode != XDP_MODE_HW)
        // dev_xdp_prog(dev, mode) 获取需要安装的 eBPF 程序
        bpf_prog_change_xdp(dev_xdp_prog(dev, mode), prog);
    ...
}
```

继续

```c
void bpf_prog_change_xdp(struct bpf_prog *prev_prog, struct bpf_prog *prog)
{
    bpf_dispatcher_change_prog(BPF_DISPATCHER_PTR(xdp), prev_prog, prog);
}
```

注意：写到这里的时候，我将研究的 Linux 内核代码从 5.19 升级到了 6.1。在 bpf 代码中，变化较大。

```c
void bpf_dispatcher_change_prog(struct bpf_dispatcher *d, struct bpf_prog *from,
                struct bpf_prog *to)
{
    bool changed = false;
    int prev_num_progs;

    // 比较from和to是否相等，若相等则直接返回；否则获取互斥锁以访问d->mutex
    if (from == to)
        return;

    mutex_lock(&d->mutex);
    if (!d->image) {
        // 分配内存
        d->image = bpf_prog_pack_alloc(PAGE_SIZE, bpf_jit_fill_hole_with_zero);
        if (!d->image)
            goto out;
        // 分配可执行内存    
        d->rw_image = bpf_jit_alloc_exec(PAGE_SIZE);
        if (!d->rw_image) {
            u32 size = PAGE_SIZE;

            bpf_arch_text_copy(d->image, &size, sizeof(size));
            bpf_prog_pack_free((struct bpf_binary_header *)d->image);
            d->image = NULL;
            goto out;
        }
        bpf_image_ksym_add(d->image, &d->ksym);
    }

    prev_num_progs = d->num_progs;
    changed |= bpf_dispatcher_remove_prog(d, from);
    changed |= bpf_dispatcher_add_prog(d, to);

    if (!changed)
        goto out;

    bpf_dispatcher_update(d, prev_num_progs);
    out:
    mutex_unlock(&d->mutex);
}
```

下面就涉及到 eBPF 程序在内核中分配内存和动态更新了，学识有限，等理解更多了再继续写。

[^1]: https://youtu.be/L3_AOFSNKK8
[^2]: https://arthurchiao.art/blog/ebpf-assembly-with-llvm-zh/#36-%E7%BC%96%E8%AF%91%E6%97%B6%E5%B5%8C%E5%85%A5%E8%B0%83%E8%AF%95%E7%AC%A6%E5%8F%B7%E6%88%96-c-%E6%BA%90%E7%A0%81clang--g--llvm-objdump--s
[^3]: https://www.mankier.com/8/bpftool-prog
[^4]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/bpf/bpftool?h=v5.15
[^5]: https://arthurchiao.art/blog/cilium-bpf-xdp-reference-guide-zh/#xdp-%E5%B7%A5%E4%BD%9C%E6%A8%A1%E5%BC%8F
[^6]: https://zhuanlan.zhihu.com/p/568056456
[^7]: https://switch-router.gitee.io/blog/bpf-3/
[^8]: https://github.com/osandov/drgn
