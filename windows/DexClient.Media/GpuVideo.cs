using System.Runtime.InteropServices;
using FFmpeg.AutoGen;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;
using ID3D11Device = Vortice.Direct3D11.ID3D11Device;
using ID3D11VideoDevice = Vortice.Direct3D11.ID3D11VideoDevice;

namespace DexClient.Media;

// One hardware Direct3D 11 device shared by the decoder and the presenter: FFmpeg
// decodes H.264 into its textures (D3D11VA) and the presenter's video processor
// converts and draws them into the swap chain, so frames never leave the GPU.
// The decoder thread and the UI thread both use it, so it is multithread protected.
public sealed unsafe class GpuVideo : IDisposable
{
    public ID3D11Device Device { get; }
    public string Adapter { get; }
    internal AVBufferRef* Ffmpeg;

    private GpuVideo(ID3D11Device device, string adapter, AVBufferRef* ffmpegDevice)
    {
        Device = device; Adapter = adapter; Ffmpeg = ffmpegDevice;
    }

    // A ready GPU path, or null with the reason (no hardware device, no video
    // support, no NV12-to-BGRA conversion, or FFmpeg cannot use the device).
    public static GpuVideo? TryCreate(out string? failure)
    {
        ID3D11Device? device = null;
        AVBufferRef* hardware = null;
        try
        {
            device = D3D11.D3D11CreateDevice(DriverType.Hardware, DeviceCreationFlags.BgraSupport | DeviceCreationFlags.VideoSupport);
            using (var multithread = device.QueryInterface<ID3D11Multithread>()) multithread.SetMultithreadProtected(true);
            string adapter;
            using (var dxgi = device.QueryInterface<IDXGIDevice>())
            using (var gpu = dxgi.GetAdapter()) adapter = gpu.Description.Description;
            CheckConversion(device);
            hardware = ffmpeg.av_hwdevice_ctx_alloc(AVHWDeviceType.AV_HWDEVICE_TYPE_D3D11VA);
            if (hardware == null) throw new InvalidOperationException("FFmpeg has no D3D11VA support.");
            var context = (AVD3D11VADeviceContext*)((AVHWDeviceContext*)hardware->data)->hwctx;
            Marshal.AddRef(device.NativePointer); // FFmpeg releases its own reference when the context is freed.
            context->device = (FFmpeg.AutoGen.ID3D11Device*)device.NativePointer;
            int status = ffmpeg.av_hwdevice_ctx_init(hardware);
            if (status < 0) throw new InvalidOperationException($"FFmpeg could not use the GPU ({status}).");
            failure = null;
            var ready = new GpuVideo(device, adapter, hardware);
            device = null; hardware = null;
            return ready;
        }
        catch (Exception e) when (e is SharpGen.Runtime.SharpGenException or InvalidOperationException or COMException)
        {
            failure = e.Message;
            return null;
        }
        finally
        {
            if (hardware != null) ffmpeg.av_buffer_unref(&hardware);
            device?.Dispose();
        }
    }

    // The presenter's conversion must work before any frame is decoded on the GPU.
    private static void CheckConversion(ID3D11Device device)
    {
        using var video = device.QueryInterface<ID3D11VideoDevice>();
        var description = Content(1920, 1080);
        video.CreateVideoProcessorEnumerator(ref description, out var enumerator).CheckError();
        using (enumerator)
        {
            var input = enumerator.CheckVideoProcessorFormat(Format.NV12);
            var output = enumerator.CheckVideoProcessorFormat(Format.B8G8R8A8_UNorm);
            if ((input & VideoProcessorFormatSupport.Input) == 0 || (output & VideoProcessorFormatSupport.Output) == 0)
                throw new InvalidOperationException("The GPU cannot convert NV12 video to BGRA.");
        }
    }

    internal static VideoProcessorContentDescription Content(int width, int height) => new()
    {
        InputFrameFormat = VideoFrameFormat.Progressive,
        InputWidth = (uint)width, InputHeight = (uint)height,
        OutputWidth = (uint)width, OutputHeight = (uint)height,
        InputFrameRate = new Rational(30, 1), OutputFrameRate = new Rational(30, 1),
        Usage = VideoUsage.PlaybackNormal,
    };

    public void Dispose()
    {
        var hardware = Ffmpeg; Ffmpeg = null;
        if (hardware != null) ffmpeg.av_buffer_unref(&hardware);
        Device.Dispose();
    }
}
