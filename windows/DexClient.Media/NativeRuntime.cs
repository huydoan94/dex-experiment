using System.ComponentModel;
using System.Runtime.InteropServices;
using FFmpeg.AutoGen;

namespace DexClient.Media;

// Process-wide initialization, before any native decoder or background work.
public static class NativeRuntime
{
    private static string? directory;
    private static nint searchCookie;

    public static unsafe object Initialize(string path, Action<string>? trace = null)
    {
        trace?.Invoke("runtime_enter");
        path = Path.GetFullPath(path);
        if (directory != null && directory != path)
            throw new InvalidOperationException("Native directory already selected.");
        if (directory == null)
        {
            if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
            trace?.Invoke("dll_search_start");
            if (!SetDefaultDllDirectories(0x00001000)) throw new Win32Exception();
            searchCookie = AddDllDirectory(path);
            if (searchCookie == 0) throw new Win32Exception();
            trace?.Invoke("binding_root_start");
            ffmpeg.RootPath = path;
            trace?.Invoke("binding_root_complete");
            directory = path; // Retained until process exit: FFmpeg bindings cache function pointers.
        }
        trace?.Invoke("avcodec_version_start");
        CheckMajor(ffmpeg.avcodec_version(), ffmpeg.LIBAVCODEC_VERSION_MAJOR, "avcodec");
        trace?.Invoke("avformat_version_start");
        CheckMajor(ffmpeg.avformat_version(), ffmpeg.LIBAVFORMAT_VERSION_MAJOR, "avformat");
        trace?.Invoke("avutil_version_start");
        CheckMajor(ffmpeg.avutil_version(), ffmpeg.LIBAVUTIL_VERSION_MAJOR, "avutil");
        trace?.Invoke("swscale_version_start");
        CheckMajor(ffmpeg.swscale_version(), ffmpeg.LIBSWSCALE_VERSION_MAJOR, "swscale");
        CheckMajor(ffmpeg.swresample_version(), ffmpeg.LIBSWRESAMPLE_VERSION_MAJOR, "swresample");
        trace?.Invoke("runtime_versions_complete");
        return new { version = ffmpeg.av_version_info(),
                     codec = ffmpeg.avcodec_version(), format = ffmpeg.avformat_version(),
                     util = ffmpeg.avutil_version(), scale = ffmpeg.swscale_version(), directory };
    }

    public static void CheckMajor(uint version, int expected, string library)
    {
        if ((version >> 16) != expected)
            throw new NotSupportedException($"{library} ABI {version >> 16}; expected {expected}.");
    }

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint flags);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint AddDllDirectory(string path);
}
