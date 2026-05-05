# 手机端无 Root 内存与堆栈调试工具设计（Android）

> 目标：在 **无 Root** 条件下，提供“可在手机端触发 + PC 端可分析”的内存与堆栈调试能力。

## 1. 能力边界

无 Root 下不能直接读取其他应用私有内存；可行方案是：

- 调试 **自己应用**：通过 `android:debuggable=true`（debug 包）+ Android Studio / adb。
- 抓 Java/Kotlin 堆：`am dumpheap` / Android Studio Profiler。
- 抓 Native 堆：`heapprofd`（Perfetto）。
- 抓卡顿/ANR 堆栈：主线程 watchdog + signal + tombstone/trace。

## 2. 工具架构

### 2.1 端侧 SDK（集成到 App）

- `MemoryProbe`
  - 采集 PSS / Java heap / native heap / graphics / code / stack。
  - 采样间隔默认 5s，可动态下发。
- `StackProbe`
  - 主线程卡顿检测（如 > 700ms）。
  - 触发时抓取：
    - 主线程栈
    - Top N 工作线程栈
    - 当前页面、路由、前后台状态
- `LeakProbe`
  - 弱引用监控 Activity/Fragment/ViewModel 生命周期。
  - 延迟二次 GC 后仍存活则上报疑似泄漏。
- `NativeProbe`
  - 可选接入 `heapprofd` session token。
  - 记录 malloc hotspot 摘要（离线分析后回灌）。

### 2.2 手机端控制台（调试页）

- 一键开始/停止采样
- 一键导出最近 10 分钟诊断包（zip）
- 查看实时曲线：
  - Java Heap
  - Native Heap
  - 线程数
  - GC 次数/耗时

### 2.3 桌面分析脚本（可选）

- 输入：诊断 zip + 可选 Perfetto trace
- 输出：
  - 峰值时间点
  - 峰值前后线程栈聚类
  - 疑似泄漏对象路径（基于 HPROF）

## 3. 关键实现点（示例代码）

### 3.1 主线程卡顿 + 堆栈抓取（Kotlin）

```kotlin
object BlockWatchdog {
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var tick = 0L

    fun start() {
        Thread {
            while (true) {
                val start = SystemClock.uptimeMillis()
                tick = start
                mainHandler.post { tick = 0L }
                Thread.sleep(700)
                if (tick != 0L) {
                    val cost = SystemClock.uptimeMillis() - start
                    val stacks = Thread.getAllStackTraces()
                    DebugReporter.reportBlock(cost, stacks)
                }
            }
        }.start()
    }
}
```

### 3.2 内存采样（Kotlin）

```kotlin
fun sampleMemory(context: Context): Map<String, Long> {
    val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val mi = ActivityManager.MemoryInfo()
    am.getMemoryInfo(mi)

    val rt = Runtime.getRuntime()
    val javaUsed = rt.totalMemory() - rt.freeMemory()

    val debug = Debug.MemoryInfo()
    Debug.getMemoryInfo(debug)

    return mapOf(
        "availMem" to mi.availMem,
        "totalMem" to mi.totalMem,
        "javaUsed" to javaUsed,
        "nativeHeap" to Debug.getNativeHeapAllocatedSize().toLong(),
        "pssTotalKb" to debug.totalPss.toLong(),
        "privateDirtyKb" to debug.totalPrivateDirty.toLong()
    )
}
```

## 4. 无 Root 调试命令速查

```bash
# 1) Java 堆导出（目标 app）
adb shell am dumpheap <package> /data/local/tmp/app.hprof
adb pull /data/local/tmp/app.hprof

# 2) 抓 ANR traces（调试机）
adb shell kill -3 <pid>
adb shell cat /data/anr/traces.txt > traces.txt

# 3) Perfetto / heapprofd（建议通过 Perfetto UI 配置）
# https://ui.perfetto.dev
```

## 5. 数据结构建议

```json
{
  "device": {"model": "Pixel 8", "api": 35},
  "app": {"versionName": "1.4.2", "build": 2042},
  "timeline": [
    {
      "ts": 1714891200000,
      "javaUsed": 132120576,
      "nativeHeap": 84541440,
      "threadCount": 96,
      "topStacks": ["main: ...", "DefaultDispatcher-worker-1: ..."]
    }
  ],
  "events": [
    {"type": "block", "costMs": 1480, "page": "FeedFragment"}
  ]
}
```

## 6. 建议落地路线（两周）

- Week 1
  - 接入 `MemoryProbe` + `StackProbe`
  - 实现调试页与本地文件导出
- Week 2
  - 接入 HPROF 分析脚本（MAT/LeakCanary Shark）
  - 接入 Perfetto trace 模板与一键说明

## 7. 安全与发布策略

- 仅在 debug / 灰度渠道启用完整栈采集。
- 线上正式版默认关闭，必要时通过远程开关短期开启。
- 栈与对象信息需做脱敏（URL/token/手机号）。

---

如果你需要，我可以下一步直接给你：
1) Android SDK 模块骨架（`debug-probe`）
2) 诊断 zip 导出代码
3) Python 离线分析脚本（自动找峰值+栈聚类）
