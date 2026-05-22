# BLAgent: Agentic RAG for File-Level Bug Localization

## PaperSearch Summary

BLAgent 是一种面向文件级缺陷定位的智能检索增强生成（Agentic RAG）框架。它通过三项核心设计提升定位精度：代码结构感知的仓库编码（路径增强的AST分块）、双视角查询转换（捕获结构和行为信号）、以及两阶段智能重排序（符号检查与证据推理结合）。与基于图或多跳的智能方法不同，BLAgent 在紧凑候选集上进行有限推理，平衡了准确性与成本。在 SWE-bench Lite 上，BLAgent 使用开源模型达到超过78%的Top-1准确率，使用闭源模型超过86%，且成本比最强基线低18倍以上。集成到自动程序修复框架后，端到端修复成功率提升超过20%。

## Notes

- 