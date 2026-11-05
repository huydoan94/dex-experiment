using System.Runtime.InteropServices;
using System.Numerics;
using System.Security.Cryptography;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;

namespace DexClient.Media;

public enum PresentationMode { PreferHardware, Software }

// UI-thread owned. Fixed fixture geometry: a production view must add resize/device-loss handling.
public sealed unsafe class FramePresenter : IDisposable
{
    private ID3D11Device? device;
    private ID3D11DeviceContext? context;
    private IDXGISwapChain1? swapChain;
    private nint panel;
    public string Driver { get; private set; } = "";
    public string Adapter { get; private set; } = "";
    public string? HardwareFailure { get; private set; }
    public int Presents { get; private set; }
    private readonly Action<string>? trace;
    private readonly int width;
    private readonly int height;

    public FramePresenter(nint panelInspectable, int width, int height, PresentationMode mode, Action<string>? trace = null)
    {
        trace?.Invoke("presenter_constructor_enter");
        if (width <= 0 || height <= 0 || width > 1920 || height > 1080)
            throw new ArgumentOutOfRangeException(nameof(width));
        this.trace = trace;
        this.width = width;
        this.height = height;
        try
        {
            Guid iid = new("63aad0b8-7c24-40ff-85a8-640d944cc325");
            trace?.Invoke("panel_query_start");
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(panelInspectable, in iid, out panel));
            trace?.Invoke("panel_queried");
            if (mode == PresentationMode.PreferHardware)
            {
                try
                {
                    device = D3D11.D3D11CreateDevice(DriverType.Hardware, DeviceCreationFlags.BgraSupport);
                    Driver = "Hardware";
                }
                catch (SharpGen.Runtime.SharpGenException e) { HardwareFailure = e.Message; }
            }
            if (device == null)
            {
                device = D3D11.D3D11CreateDevice(DriverType.Warp, DeviceCreationFlags.BgraSupport);
                Driver = "WARP";
            }
            trace?.Invoke("device_created " + Driver);
            context = device.ImmediateContext;
            using var dxgi = device.QueryInterface<IDXGIDevice>();
            using var adapter = dxgi.GetAdapter();
            Adapter = adapter.Description.Description;
            using var factory = adapter.GetParent<IDXGIFactory2>();
            var description = new SwapChainDescription1
            {
                Width = (uint)width, Height = (uint)height, Format = Format.B8G8R8A8_UNorm,
                BufferCount = 2, BufferUsage = Usage.RenderTargetOutput,
                SampleDescription = new SampleDescription(1, 0), Scaling = Scaling.Stretch,
                SwapEffect = SwapEffect.FlipSequential, AlphaMode = AlphaMode.Ignore
            };
            swapChain = factory.CreateSwapChainForComposition(device, description);
            trace?.Invoke("swapchain_created");
            SetSwapChain(swapChain.NativePointer);
            trace?.Invoke("swapchain_attached");
        }
        catch { Dispose(); throw; }
    }

    public string Present(VideoFrame frame)
    {
        ObjectDisposedException.ThrowIf(swapChain == null, this);
        if (frame.Width != width || frame.Height != height || frame.Bgra.Length != width * height * 4)
            throw new ArgumentException("Frame geometry differs from the surface.");
        using var backBuffer = swapChain!.GetBuffer<ID3D11Texture2D>(0);
        trace?.Invoke("upload");
        context!.UpdateSubresource(frame.Bgra, backBuffer, 0, (uint)(width * 4), 0);
        var stagingDescription = backBuffer.Description;
        stagingDescription.Usage = ResourceUsage.Staging;
        stagingDescription.BindFlags = BindFlags.None;
        stagingDescription.CPUAccessFlags = CpuAccessFlags.Read;
        stagingDescription.MiscFlags = ResourceOptionFlags.None;
        using var staging = device!.CreateTexture2D(stagingDescription);
        context.CopyResource(staging, backBuffer);
        trace?.Invoke("map_start");
        var mapped = context.Map(staging, 0, MapMode.Read, Vortice.Direct3D11.MapFlags.None);
        trace?.Invoke("map_complete");
        var readback = new byte[frame.Bgra.Length];
        try
        {
            for (int y = 0; y < height; y++)
                Marshal.Copy(mapped.DataPointer + checked(y * (int)mapped.RowPitch),
                             readback, y * width * 4, width * 4);
        }
        finally { context.Unmap(staging, 0); }
        if (!readback.AsSpan().SequenceEqual(frame.Bgra))
            throw new InvalidDataException("D3D readback differs from decoded pixels.");
        trace?.Invoke("present_start");
        swapChain.Present(1, PresentFlags.None).CheckError();
        trace?.Invoke("present_complete");
        Presents++;
        return Convert.ToHexString(SHA256.HashData(readback));
    }

    public bool LayoutScaleVerified { get; private set; }
    public void SetLayoutSize(double layoutWidth, double layoutHeight)
    {
        ObjectDisposedException.ThrowIf(swapChain == null, this);
        if (!double.IsFinite(layoutWidth) || !double.IsFinite(layoutHeight) || layoutWidth <= 0 || layoutHeight <= 0) return;
        var expected = Matrix3x2.CreateScale((float)(layoutWidth / width), (float)(layoutHeight / height));
        using var composed = swapChain!.QueryInterface<IDXGISwapChain2>();
        composed.MatrixTransform = expected;
        var actual = composed.MatrixTransform;
        LayoutScaleVerified = Math.Abs(actual.M11 - expected.M11) < .0001f && Math.Abs(actual.M22 - expected.M22) < .0001f;
        if (!LayoutScaleVerified) throw new InvalidDataException("Swap-chain layout transform mismatch.");
    }

    // Production frames do not create a staging texture, read back pixels or
    // hash screen content. The synthetic Present method retains that check.
    public void PresentLive(VideoFrame frame)
    {
        ObjectDisposedException.ThrowIf(swapChain == null, this);
        if (frame.Width != width || frame.Height != height || frame.Bgra.Length != checked(width * height * 4))
            throw new ArgumentException("Frame geometry differs from the surface.");
        using var buffer = swapChain!.GetBuffer<ID3D11Texture2D>(0);
        context!.UpdateSubresource(frame.Bgra, buffer, 0, (uint)(width * 4), 0);
        swapChain.Present(0, PresentFlags.None).CheckError();
        Presents++;
    }

    private void SetSwapChain(nint value)
    {
        // ISwapChainPanelNative follows IUnknown; SetSwapChain is its fourth slot.
        var method = (delegate* unmanaged[Stdcall]<nint, nint, int>)(*(nint**)panel)[3];
        Marshal.ThrowExceptionForHR(method(panel, value));
    }

    public void Dispose()
    {
        try { if (panel != 0) SetSwapChain(0); }
        finally
        {
            if (panel != 0) { Marshal.Release(panel); panel = 0; }
            swapChain?.Dispose(); swapChain = null;
            context?.ClearState();
            context?.Flush();
            context?.Dispose(); context = null;
            device?.Dispose(); device = null;
        }
    }
}
