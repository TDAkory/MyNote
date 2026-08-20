# Index Policy

本文约定 `MyNote` 中各级 `INDEX.md` 的职责，避免同一篇笔记在多个上层索引里重复出现。

## 1. 核心原则

`INDEX.md` 采用分层导航，而不是全量递归目录树。

```text
顶层 index
  -> 一级主题 index
    -> 二级模块 index
      -> 叶子专题 index
        -> 具体文章
```

一篇具体文章通常只应该出现在它所属专题的 index 中；上层 index 只链接到下一级目录的 index 或 README。

## 2. 各级职责

| 层级 | 示例 | 职责 | 是否展开具体文章 |
| --- | --- | --- | --- |
| 顶层索引 | `MyNoteINDEX.md` | 只列一级主题入口 | 否 |
| 一级主题索引 | `AppFrameThoughtsINDEX.md`、`CppLearnINDEX.md` | 只列主题下的模块入口 | 否 |
| 二级模块索引 | `AIINDEX.md`、`TopicsINDEX.md` | 列子专题入口，可列少量直属文章 | 不展开子专题内部文章 |
| 叶子专题索引 | `PSINDEX.md`、`KVCacheINDEX.md`、`HPC_LibrariesINDEX.md` | 维护本专题具体文章和阅读顺序 | 是 |
| Roadmap | `000_ps_roadmap.md` | 解释学习顺序、阶段目标、产出要求 | 按学习顺序引用必要文章 |

## 3. 具体规则

### 3.1 上层 index 只列下一层

例如 `AppFrameThoughtsINDEX.md` 应该列：

```text
09_AI -> 09_AI/AIINDEX.md
05_Storage -> 05_Storage/StorageINDEX.md
```

不应该列：

```text
09_AI/PS/014_ps_float_compression.md
09_AI/KVCache/010_phase0_kv_cache_foundation.md
```

这些具体文章交给 `PSINDEX.md`、`KVCacheINDEX.md` 等叶子专题 index 管理。

### 3.2 叶子专题 index 管具体文章

例如 `PSINDEX.md` 可以列：

```text
000_ps_roadmap.md
010_ps_note.md
011_ps_sharding.md
012_ps_comm.md
013_parallelism_and_ps_fusion.md
014_ps_float_compression.md
090_ps_kvcache_unified_state_architecture.md
```

### 3.3 Roadmap 不替代 index

`INDEX.md` 回答“这里有什么”。

`roadmap.md` 回答“应该按什么顺序学，为什么这么学”。

两者可以互相链接，但不要让 roadmap 变成完整目录树，也不要让 index 承担过多学习计划说明。

### 3.4 外部跨专题引用保持低密度

专题 index 可以有“相关专题”区，但只放强相关入口，不做大范围复制。

例如 `PSINDEX.md` 可以链接：

```text
../302_optimizers.md
../301_training_tech.md
```

但不应展开这些文件的内部目录。

## 4. 生成脚本策略

`python3 mynote.py index gen <目录>` 默认只生成当前目录的下一层内容：

1. 子目录优先链接到子目录自己的 `*INDEX.md`。
2. 如果没有 `*INDEX.md`，再链接 `README.md`。
3. 上层 index 不递归展开子目录内部文件。
4. 需要专题内完整文章列表时，在该专题目录自己的 index 中生成。

如果确实需要旧式递归目录树，应通过显式参数启用，而不是作为默认行为。

## 5. 手写 index 保护

部分叶子专题 index 不只是机械目录，还包含学习路线和维护原则，例如：

```text
PyTorchINDEX.md
HPC_LibrariesINDEX.md
PSINDEX.md
KVCacheINDEX.md
```

这类 index 可以手写维护。运行 `python3 mynote.py index gen <目录>` 后，需要抽查这些专题 index 是否被覆盖；如果被覆盖，应恢复其 roadmap / 当前原则等说明内容。

## 6. Index 文件命名规则

为了在文档拓扑图中区分不同节点，index 文件不统一命名为 `INDEX.md`，而采用：

```text
<语义名>INDEX.md
```

### 6.1 数字前缀目录去数字

目录编号只表示排序，不进入 index 文件名。

```text
09_AI                  -> AIINDEX.md
01_Computer            -> ComputerINDEX.md
02_CompressionEncoding -> CompressionEncodingINDEX.md
```

### 6.2 叶子专题使用专题名

```text
PS                  -> PSINDEX.md
KVCache             -> KVCacheINDEX.md
PyTorch             -> PyTorchINDEX.md
RecommenderSystem   -> RecommenderSystemINDEX.md
HPC_Libraries       -> HPCLibrariesINDEX.md
```

### 6.3 通用目录名加父级语义前缀

对于 `Basics`、`Packages`、`cache`、`network`、`Z-Books` 等容易在多个路径重复的目录，index 文件名需要加父级限定：

```text
GoLearn/Basics            -> GoBasicsINDEX.md
RustLearn/Basics          -> RustBasicsINDEX.md
JavaLearn/basics          -> JavaBasicsINDEX.md
LinuxLearn/basics         -> LinuxBasicsINDEX.md
GoLearn/Packages          -> GoPackagesINDEX.md
PythonLearn/Packages      -> PythonPackagesINDEX.md
LinuxLearn/source_code/network -> LinuxSourceNetworkINDEX.md
```

### 6.4 已有命名逐步迁移

已有 index 文件如果已经被大量链接引用，不强制一次性重命名。后续迁移时按以下顺序：

1. 先更新生成脚本规则；
2. 再迁移明显冲突或不自然的文件名；
3. 同步修正所有入链；
4. 最后检查全仓 index 文件名是否仍有重复。
