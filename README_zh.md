## Ketones: A kempt eBPF tool for a new environments

欢迎使用我们的软件！以下是关于软件的详细描述，让您了解它的功能和特点。

### 软件概述

我们的软件是一个强大的eBPF程序集，旨在帮助用户在各种环境中运行程序。它专注于取
代BCC工具集，并通过自研工具提供了更多观察内核的功能。我们的软件具有小巧的体积,
易于集成，并且能够在各种内核上运行。无需安装编译环境，我们的软件支持容器环境运
行，为您节省宝贵的时间。

### 主要功能

**替代BCC工具集**：我们的软件的首要目标是取代BCC工具集。我们提供了一套自研工具
，以更好地观察和分析内核。
**内核观察工具**：我们的软件内置了一些用于观察内核的工具，使您能够深入了解系统
的内部运行情况。
**快速修复和迭代**：我们致力于快速修复和改进软件，以解决各种兼容性问题，确保您
始终使用最稳定和可靠的版本。
**无缝兼容性**：我们的软件可以与BCC工具集无缝兼容，您可以轻松迁移和使用我们的软
件而不会受到任何影响。

### 主要特点

**跨平台支持**：我们的软件可以在任何操作系统上运行，为您提供了广泛的使用选择。
**多架构支持**：我们的软件支持ARM64、X86、Loongarch、RISC-V架构，满足不同硬件平
台的需求。

### 编译

***安装编译依赖***

```bash
# apt install llvm-dev clang make gcc libcap-dev binutils-dev libnuma-dev
or
# yum install clang make gcc llvm elfutils-libelf-devel numactl-devel ncurses-devel
```

***编译***

```bash
# make -j8
```

***安装***

```bash
# make install
```

### 集成

我们的软件设计为简单易用，并具备轻松的安装和集成过程。您只需按照以下步骤即可开
始使用：

下载软件包并解压缩到您的目标系统。
配置软件的运行环境，我们的软件无需额外的编译环境。
在您的容器环境中启动我们的软件，您将立即享受到内核观察的便利。
请注意，我们提供了详细的安装指南和使用文档，以帮助您顺利开始使用我们的软件。

### 如何贡献

我们热忱欢迎软件社区的贡献者！如果您对软件有任何改进或新功能的建议，请随时联系
我们。您可以通过报告问题、提交请求或参与讨论来为软件发展做出贡献。我们的团队将
与您密切合作，确保做出成功的贡献。

