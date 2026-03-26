# APK 全量对比工具（apkdiff）

这个工具用于**上传/输入两个完整 APK 文件**（不是 dex），自动做多维度差异对比，并输出结构化报告，方便调试人员定位“这个版本和原来到底哪里不一样”。

## 支持对比的维度

- 基础信息对比（包名、versionName、versionCode、minSdk、targetSdk）
- Manifest 组件对比（权限、Activity、Service、Receiver、Provider）
- 资源和打包内容对比（文件列表、native so）
- DEX 层对比
  - 类级别差异（before-only / after-only / both）
  - 方法级别差异
  - **函数返回值类型变化**（同名同参数方法，返回类型不同）
- API/协议信号对比
  - 从 DEX 字符串中提取 URL，进行 before/after 对比

> 输出是“对比视角”，不是只说“增加了什么”，而是展示 before/after 的对应关系与差异集合。

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 使用

```bash
python -m apkdiff.compare old.apk new.apk -o report.json
```

执行后会生成 `report.json`，包含：

- `inputs.before` / `inputs.after`：两个 APK 的完整快照
- `summary`：核心版本指标对比
- `manifest_diff`：清单差异
- `resource_diff`：资源/文件差异
- `dex_diff`：类、方法、返回类型变化
- `protocol_api_signals`：URL 协议信号差异

## 输出示例（节选）

```json
{
  "summary": {
    "version_name": { "before": "2.3.1", "after": "2.4.0" },
    "method_count": { "before": 10321, "after": 10509 }
  },
  "dex_diff": {
    "methods": {
      "return_type_changed": [
        {
          "method": "com.example.api.Client->fetch(java.lang.String)",
          "before_return": "java.lang.String",
          "after_return": "retrofit2.Response"
        }
      ]
    }
  }
}
```

## 后续可扩展

- 增加 HTML 可视化报告
- 增加 class/method 白名单和包过滤
- 增加 smali 级语义 diff（基本块/调用链变化）
- 增加 CI 集成（提交 APK 后自动跑对比）
