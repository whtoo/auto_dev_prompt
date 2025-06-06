# 自动化开发提示文档系统

## 项目概述

这是一个旨在为大型语言模型(LLMs)提供合适角色提示(prompt)的系统，为不同开发角色（产品经理、需求分析师、前端工程师、后端工程师）提供通用的工作规范和流程指南，是实现开发流程agent自动化的一次尝试。本项目通过标准化的工作流程和文档模板，帮助LLMs更好地扮演开发团队中的不同角色，提高自动化开发效率和协作质量。

## 项目背景

随着AI技术的发展，大型语言模型(LLMs)在自然语言处理、代码生成等领域展现出强大的能力。然而，在实际开发项目中，LLMs的能力还存在一些局限性，例如：
- **角色理解不足**：LLMs对于不同角色的理解存在差异，可能无法准确地理解和执行不同角色的工作流程。
- **文档交互不足**：LLMs在处理文档时，可能无法直接与文档进行交互，导致文档内容的准确性和一致性受到限制。
- **工作流程不标准化**：不同开发团队的工作流程和规范可能存在差异，导致LLMs在不同团队中的应用存在问题。
为了解决这些问题，本项目旨在通过标准化的工作流程和文档模板，为不同开发角色提供合适的角色提示(prompt)，帮助LLMs更好地扮演开发团队中的不同角色，提高自动化开发效率和协作质量。

## 项目目标

- 为不同开发角色提供合适的角色提示(prompt)，帮助LLMs更好地理解和执行不同角色的工作流程。
- 提供标准化的工作流程和文档模板，帮助开发团队更好地管理和执行工作流程。
- 提高LLMs在文档处理和工作流程管理方面的能力，提高自动化开发效率和协作质量。

## 文件结构

- `api_interface_specification.md` - 前后端API接口规范文档
- `product_manager_prompt.md` - 产品经理工作流程和PRD文档管理指南
- `requirements_analyst_prompt.md` - 需求分析师工作流程和技术需求说明书生成指南
- `frontend_engineer_prompt.md` - 前端工程师工作流程指南
- `backend_engineer_prompt.md` - 后端工程师工作流程指南
- `docs/` - 项目文档目录
  - `requirement_quiz/` - 需求收集问答文档
  - `requirement_prod/` - 产品需求文档(PRD)
  - `technical_spec/` - 技术需求说明书

## 使用方法

本系统设计为与大型语言模型(LLM)配合使用，为开发团队提供自动化的工作流程支持：

1. **需求收集与管理**：
   - 产品经理使用 `product_manager_prompt.md` 作为提示指南
   - 通过文档交互进行需求收集和确认
   - 生成标准化的PRD文档并存储在 `docs/requirement_prod/` 目录

2. **需求分析与转化**：
   - 需求分析师使用 `requirements_analyst_prompt.md` 作为提示指南
   - 将PRD转化为技术需求说明书
   - 输出文档保存在 `docs/technical_spec/` 目录

3. **前后端开发**：
   - 前端工程师使用 `frontend_engineer_prompt.md` 作为提示指南
   - 后端工程师使用 `backend_engineer_prompt.md` 作为提示指南
   - 遵循 `api_interface_specification.md` 中的接口规范进行开发
4. **测试与部署**：
   - 前后端工程师完成开发后，进行测试和部署
   - 测试通过后，文档交互进行确认和记录
   - 部署完成后，更新相关文档并记录版本信息


## 项目特点

- **标准化流程**：为每个角色定义清晰的工作流程和责任
- **文档模板**：提供统一的文档格式和规范
- **版本控制**：内置文档版本管理机制
- **自动化交互**：通过文档交互方式收集和确认需求
- **全流程覆盖**：从需求收集到技术实现的完整开发流程支持

## 如何开始

1. 创建必要的目录结构：
   ```
   mkdir -p docs/requirement_quiz docs/requirement_prod docs/technical_spec
   ```

2. 使用产品经理提示文档启动需求收集流程
3. 完成需求收集后，使用需求分析师提示文档进行需求转化
4. 前后端工程师根据技术需求说明书和接口规范进行开发

## 贡献指南

欢迎对本项目进行贡献。请遵循以下步骤：

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开一个 Pull Request

## 许可证

本项目采用 [LICENSE](LICENSE) 文件中规定的许可证。 