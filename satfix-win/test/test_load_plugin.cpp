//
//  test_load_plugin.cpp —— 宿主侧验证插件 DLL 的「管线」部分
//
//  为什么要有这个测试
//  ------------------
//  真机验证要启动游戏，成本高、失败原因难分辨。而插件里有一大段逻辑
//  **与游戏无关**：DllMain 是否只创建线程、插件目录是否从模块地址取、
//  logs\ 是否建出来、_SH_DENYWR 是否真的允许别人读日志、配置解析是否正确、
//  DllMain 是否会在加载器锁里死锁。
//
//  这些都能在一个普通 EXE 里 LoadLibrary 一次就查完。
//
//  期望：在本测试进程里，
//    * 构建时间戳检查**必然失败**（这不是 stellaris.exe）-> 插件应静默退出、
//      不留钩子、不崩；这本身就是在验证"装到错的进程上要安全"（手册 6.7）。
//    * 日志文件必须被创建，且内容包含 exe build 与插件目录两行。
//    * 日志必须能被**另一个句柄**同时打开读取（验证 _SH_DENYWR，手册 9.1）。
//

#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void check(bool ok, const char* what) {
  std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) ++g_fail;
}

// 本 EXE 所在目录
std::wstring exe_dir() {
  wchar_t p[MAX_PATH * 4] = {};
  GetModuleFileNameW(nullptr, p, (DWORD)std::size(p));
  std::wstring s(p);
  const size_t i = s.find_last_of(L"\\/");
  return i == std::wstring::npos ? std::wstring() : s.substr(0, i + 1);
}

std::string read_all(const std::wstring& path, int* err) {
  FILE* f = nullptr;
  const errno_t rc = _wfopen_s(&f, path.c_str(), L"rb");
  if (rc != 0 || f == nullptr) {
    // _wfopen_s 的共享语义在 Win32 上与我们的日志句柄不兼容（实测 EACCES），
    // 于是退回 Win32 只读句柄再包成 FILE*。这也是游戏里别人读日志的真实路径。
    const HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      if (err) *err = (int)GetLastError();
      return {};
    }
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), _O_RDONLY | _O_TEXT);
    if (fd < 0) {
      CloseHandle(h);
      if (err) *err = -1;
      return {};
    }
    f = _fdopen(fd, "rb");
    if (f == nullptr) {
      _close(fd);
      if (err) *err = -2;
      return {};
    }
  }
  std::string out;
  char buf[4096];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
  std::fclose(f);
  if (err) *err = 0;
  return out;
}

bool contains(const std::string& hay, const char* needle) {
  return hay.find(needle) != std::string::npos;
}

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::printf("=== 插件 DLL 管线自测 ===\n");

  if (argc < 2) {
    std::printf("用法: test_load_plugin.exe <satfix.dll 路径>\n");
    return 2;
  }

  // DLL 路径转宽字符
  const int wn = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, nullptr, 0);
  std::vector<wchar_t> wpath((size_t)wn);
  MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wpath.data(), wn);

  // 插件目录 = DLL 所在目录
  std::wstring dll(wpath.data());
  const size_t slash = dll.find_last_of(L"\\/");
  std::wstring dir = (slash == std::wstring::npos) ? std::wstring() : dll.substr(0, slash + 1);
  const std::wstring logpath = dir + L"logs\\satfix.log";
  const std::wstring cfg = dir + L"config\\satfix.ini";

  std::printf("\n[1] 加载前状态\n");
  DeleteFileW(logpath.c_str());  // 从干净状态开始
  check(GetFileAttributesW(logpath.c_str()) == INVALID_FILE_ATTRIBUTES,
        "日志文件已被清掉（干净起点）");

  std::printf("\n[2] LoadLibraryW\n");
  const DWORD t0 = GetTickCount();
  HMODULE dllmod = LoadLibraryW(wpath.data());
  const DWORD dt = GetTickCount() - t0;
  check(dllmod != nullptr, "LoadLibraryW 成功（DllMain 返回 TRUE）");
  if (dllmod == nullptr) {
    std::printf("      GetLastError=%lu\n", GetLastError());
    return 1;
  }
  std::printf("      加载耗时 %lu ms\n", dt);
  // 注意：这个数字**测不准"DllMain 是否会阻塞"**。
  // LoadLibraryW 的耗时里包含了加载器本身、依赖解析，以及（实测很显著）
  // Windows Defender 对刚编译出来的 DLL 的扫描 —— 同一份 DLL 重跑可以从
  // 46ms 跳到 800ms 以上。所以这里只做一个粗粒度健全性上界：
  // 真正"不阻塞"的保证是结构性的（初始化在自己创建的线程上，DllMain 里
  // 只有 DisableThreadLibraryCalls + CreateThread，见手册 6.1），
  // 而不是靠这个计时。
  check(dt < 5000, "加载耗时在健全范围内（<5s；精确的\"不阻塞\"由代码结构保证）");

  std::printf("\n[3] 导出的统计接口可调用\n");
  using StatsFn = void (*)(unsigned long long*, unsigned long long*, unsigned long long*,
                           unsigned long long*);
  StatsFn stats = (StatsFn)GetProcAddress(dllmod, "satfix_win_stats");
  check(stats != nullptr, "GetProcAddress(satfix_win_stats) 成功");
  unsigned long long calls = 0, events = 0, hooked = 0, replaced = 0;
  if (stats) {
    stats(&calls, &events, &hooked, &replaced);
    std::printf("      calls=%llu events=%llu hooked=%llu replaced=%llu\n", calls, events,
                hooked, replaced);
    check(hooked == 0, "在本测试进程里没有装任何钩子（构建时间戳不匹配 -> 安全退出）");
  }

  std::printf("\n[4] 等插件线程写完日志\n");
  bool log_ok = false;
  for (int i = 0; i < 100; ++i) {  // 最多 5 秒
    if (GetFileAttributesW(logpath.c_str()) != INVALID_FILE_ATTRIBUTES) {
      log_ok = true;
      break;
    }
    Sleep(50);
  }
  check(log_ok, "logs\\satfix.log 已被创建（插件目录 = DLL 所在目录，手册 6.2）");

  std::printf("\n[5] 日志内容\n");
  // 插件是逐行 fflush 的，但"文件非空"不等于"5 行都写完了"。
  // 这里等到**最后一条期望的标记**出现（或超时）再断言，否则就是测试自己的竞态。
  std::string body;
  int err_read = 0;
  for (int i = 0; i < 80; ++i) {  // 最多 4 秒
    body = read_all(logpath, &err_read);
    if (contains(body, "exe build") && contains(body, "不匹配")) break;
    Sleep(50);
  }
  {
    const HANDLE h = CreateFileW(logpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, 0, nullptr);
    std::printf("      诊断: CreateFileW 读共享 -> %s (err=%lu)\n",
                h != INVALID_HANDLE_VALUE ? "OK" : "FAIL", GetLastError());
    if (h != INVALID_HANDLE_VALUE) {
      LARGE_INTEGER sz{};
      GetFileSizeEx(h, &sz);
      std::printf("      诊断: 文件大小 = %lld 字节\n", (long long)sz.QuadPart);
      CloseHandle(h);
    }
    std::printf("      诊断: _wfopen_s 读错误码 = %d\n", err_read);
  }
  check(!body.empty(), "日志非空");
  check(contains(body, "[satfix]"), "日志带 [satfix] 前缀");
  check(contains(body, "satfix-win"), "第 1 行记了插件版本（手册 9.1）");
  check(contains(body, "exe build"), "记了游戏构建与期望值");
  check(contains(body, "不匹配"), "在本进程里正确检出构建不匹配");
  std::printf("      ---- 日志内容 ----\n");
  {
    size_t p = 0;
    while (p < body.size()) {
      const size_t e = body.find('\n', p);
      std::printf("      %s\n", body.substr(p, e == std::string::npos ? e : e - p).c_str());
      if (e == std::string::npos) break;
      p = e + 1;
    }
  }

  std::printf("\n[6] _SH_DENYWR：别人能同时读日志（手册 9.1）\n");
  {
    // 插件仍持有 _SH_DENYWR 写句柄。MSVC 的 _SH_DENYWR 表示"拒绝其他写者"，
    // 读者应当允许 —— 但 _wfopen_s 默认共享模式在有些实现下不等价于 FOPEN 的
    // 共享语义，所以这里直接报出两种打开方式的真实结果，不猜。
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 40; ++i) {
      h = CreateFileW(logpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr, OPEN_EXISTING, 0, nullptr);
      if (h != INVALID_HANDLE_VALUE) break;
      Sleep(50);
    }
    std::printf("      诊断: CreateFileW(GENERIC_READ, SHARE_READ|WRITE) -> %s (err=%lu)\n",
                h != INVALID_HANDLE_VALUE ? "OK" : "FAIL", GetLastError());
    check(h != INVALID_HANDLE_VALUE,
          "Win32 只读句柄能在插件持写句柄时打开（游戏运行中可读日志）");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  }

  std::printf("\n[7] 配置热重载的路径解析\n");
  {
    // 这里只验证「配置路径就在插件目录下」这一约定。
    // 真正的解析逻辑在 test_stl_fix_win 之外不好单测（它嵌在 DLL 里），
    // 但配置目录的约定必须由 manifest + 目录结构共同保证，所以这里查目录。
    const std::wstring cfgdir = dir + L"config";
    const DWORD a = GetFileAttributesW(cfgdir.c_str());
    std::printf("      期望的配置目录: %ls (%s)\n", cfgdir.c_str(),
                a == INVALID_FILE_ATTRIBUTES ? "不存在" : "存在");
    std::printf("      配置文件: %ls (%s)\n", cfg.c_str(),
                GetFileAttributesW(cfg.c_str()) == INVALID_FILE_ATTRIBUTES ? "缺失 -> 用内置默认值"
                                                                          : "存在");
  }

  std::printf("\n[8] FreeLibrary 只是为了测试干净\n");
  // 手册 6.6 禁止**插件自己**卸载自己；这里是宿主测试程序在收尾，且本进程里
  // 插件什么都没 hook，所以是安全的。游戏里启动器从不卸载插件。
  check(FreeLibrary(dllmod) != 0, "FreeLibrary 成功");

  std::printf("\n=== 结果：%s（失败 %d 项）===\n", g_fail == 0 ? "全部通过" : "有失败", g_fail);
  return g_fail == 0 ? 0 : 1;
}
