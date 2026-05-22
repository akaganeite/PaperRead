# Three Heads Are Better Than One: A Multi-perspective Reasoning Framework for Enhanced Vulnerability Detection

## PaperSearch Summary

ReasonVul是一个多视角推理框架，通过三个专门的大语言模型智能体分别模拟不同推理模式，独立分析源代码后通过结构化辩论机制进行迭代反驳和修订，最终达成协作判断。在PrimeVul数据集上，ReasonVul的PairAcc达到40.00%，F1分数为72.52%，PairAcc比最佳基线提升81.24%。在JITVUL数据集上PairAcc为28.67%，验证了其泛化能力。对542个冲突案例的分析显示，其中389个被正确解决，表明辩论驱动的纠错机制能有效发现隐藏漏洞。该工作强调了多视角推理和协作验证在实现鲁棒且全面的漏洞检测中的重要性。

## Notes

- 