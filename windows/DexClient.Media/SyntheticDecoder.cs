using System.Diagnostics;
using FFmpeg.AutoGen;

namespace DexClient.Media;

public sealed class VideoFrame(int width, int height, byte[] bgra, long timestamp) : IDisposable
{
    public int Width { get; } = width;
    public int Height { get; } = height;
    public byte[] Bgra { get; } = bgra;
    public long Timestamp { get; } = timestamp;
    public long? PresentationMicroseconds { get; init; }
    internal Action<byte[]>? Recycle;
    public void Dispose() => Interlocked.Exchange(ref Recycle, null)?.Invoke(Bgra);
}
public sealed record DecodeResult(int Frames, int Width, int Height, VideoFrame LastFrame);

// Bounded finite MPEG-TS decoder; memory AVIO never opens a media file or network URL.
public static unsafe class SyntheticDecoder
{
    public static DecodeResult Decode(string path, CancellationToken cancellation, Action? firstFrame = null)
    {
        cancellation.ThrowIfCancellationRequested();
        if (!File.Exists(path)) throw new FileNotFoundException("Local fixture required.", path);
        if (new FileInfo(path).Length > 4 * 1024 * 1024) throw new InvalidDataException("Fixture too large.");
        return DecodeInput(Path.GetFullPath(path), null, cancellation, firstFrame);
    }

    public const int MaximumInputBytes = 8 * 1024 * 1024;
    private struct MemoryInput { public byte* Data; public int Length; public int Offset; }

    public static DecodeResult DecodeMemory(byte[] data, int length, CancellationToken cancellation, Action? firstFrame = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        cancellation.ThrowIfCancellationRequested();
        if (length <= 0 || length > data.Length || length > MaximumInputBytes)
            throw new InvalidDataException("Memory input outside bounds.");
        fixed (byte* bytes = data)
        {
            var source = new MemoryInput { Data = bytes, Length = length };
            return DecodeInput(null, &source, cancellation, firstFrame);
        }
    }

    private static int ReadMemory(void* opaque, byte* buffer, int size)
    {
        var source = (MemoryInput*)opaque;
        if (source == null || buffer == null || size <= 0) return ffmpeg.AVERROR_INVALIDDATA;
        int remaining = source->Length - source->Offset;
        if (remaining == 0) return ffmpeg.AVERROR_EOF;
        int count = Math.Min(size, remaining);
        Buffer.MemoryCopy(source->Data + source->Offset, buffer, size, count);
        source->Offset += count;
        return count;
    }

    private static DecodeResult DecodeInput(string? path, MemoryInput* source, CancellationToken cancellation, Action? firstFrame)
    {
        AVFormatContext* format = null;
        AVIOContext* input = null;
        byte* inputBuffer = null;
        avio_alloc_context_read_packet readMemory = ReadMemory;
        AVCodecContext* context = null;
        AVPacket* packet = null;
        AVFrame* frame = null;
        SwsContext* scaler = null;
        AVDictionary* options = null;
        AVDictionary** probeOptions = stackalloc AVDictionary*[4];
        for (int i = 0; i < 4; i++) probeOptions[i] = null;
        VideoFrame? last = null;
        int count = 0;
        var clock = Stopwatch.StartNew();
        try
        {
            Check(ffmpeg.av_dict_set(&options, "protocol_whitelist", "file", 0));
            format = ffmpeg.avformat_alloc_context();
            if (format == null) throw new OutOfMemoryException();
            format->max_streams = 4;
            format->probesize = 262144;
            format->max_analyze_duration = 1000000;
            if (source != null)
            {
                inputBuffer = (byte*)ffmpeg.av_malloc(32768);
                if (inputBuffer == null) throw new OutOfMemoryException();
                input = ffmpeg.avio_alloc_context(inputBuffer, 32768, 0, source, readMemory, default, default);
                if (input == null) throw new OutOfMemoryException();
                format->pb = input;
                format->flags |= ffmpeg.AVFMT_FLAG_CUSTOM_IO;
            }
            Check(ffmpeg.avformat_open_input(&format, path,
                                            ffmpeg.av_find_input_format("mpegts"), &options));
            if (format->nb_streams == 0 || format->nb_streams > 4)
                throw new InvalidDataException("Fixture stream count outside bounds.");
            format->max_streams = (int)format->nb_streams;
            for (int i = 0; i < format->nb_streams; i++)
                Check(ffmpeg.av_dict_set(probeOptions + i, "max_pixels", "2073600", 0));
            Check(ffmpeg.avformat_find_stream_info(format, probeOptions));
            AVCodec* codec = null;
            int stream = ffmpeg.av_find_best_stream(format, AVMediaType.AVMEDIA_TYPE_VIDEO,
                                                   -1, -1, &codec, 0);
            Check(stream);
            context = ffmpeg.avcodec_alloc_context3(codec);
            if (context == null) throw new OutOfMemoryException();
            Check(ffmpeg.avcodec_parameters_to_context(context, format->streams[stream]->codecpar));
            context->max_pixels = 1920 * 1080;
            if (context->width > 1920 || context->height > 1080)
                throw new InvalidDataException("Fixture dimensions exceed limits.");
            context->thread_count = 1;
            Check(ffmpeg.avcodec_open2(context, codec, null));
            packet = ffmpeg.av_packet_alloc();
            frame = ffmpeg.av_frame_alloc();
            if (packet == null || frame == null) throw new OutOfMemoryException();
            while (true)
            {
                CheckDeadline();
                int read = ffmpeg.av_read_frame(format, packet);
                if (read == ffmpeg.AVERROR_EOF) break;
                Check(read);
                try
                {
                    if (packet->stream_index != stream) continue;
                    Check(ffmpeg.avcodec_send_packet(context, packet));
                    Drain();
                }
                finally { ffmpeg.av_packet_unref(packet); }
            }
            Check(ffmpeg.avcodec_send_packet(context, null));
            Drain(); // Delayed B frames must be included at EOF.
            if (last == null) throw new InvalidDataException("No decoded picture.");
            return new DecodeResult(count, last.Width, last.Height, last);
        }
        finally
        {
            ffmpeg.sws_freeContext(scaler);
            var frameToFree = frame;
            ffmpeg.av_frame_free(&frameToFree);
            ffmpeg.av_packet_free(&packet);
            var contextToFree = context;
            ffmpeg.avcodec_free_context(&contextToFree);
            ffmpeg.avformat_close_input(&format);
            // FFmpeg may replace the AVIO buffer, so free the current pointer.
            if (input != null)
            {
                ffmpeg.av_free(input->buffer);
                input->buffer = null;
                ffmpeg.avio_context_free(&input);
            }
            else ffmpeg.av_free(inputBuffer);
            GC.KeepAlive(readMemory);
            ffmpeg.av_dict_free(&options);
            for (int i = 0; i < 4; i++) ffmpeg.av_dict_free(probeOptions + i);
        }

        void CheckDeadline()
        {
            cancellation.ThrowIfCancellationRequested();
            if (clock.Elapsed > TimeSpan.FromSeconds(5)) throw new TimeoutException("Fixture decode deadline.");
        }
        void Drain()
        {
            while (true)
            {
                CheckDeadline();
                int received = ffmpeg.avcodec_receive_frame(context, frame);
                if (received == ffmpeg.AVERROR(ffmpeg.EAGAIN) || received == ffmpeg.AVERROR_EOF) return;
                Check(received);
                try
                {
                    if (++count > 120 || frame->width <= 0 || frame->height <= 0 ||
                        frame->width > 1920 || frame->height > 1080)
                        throw new InvalidDataException("Fixture decode bounds exceeded.");
                    scaler = ffmpeg.sws_getCachedContext(scaler, frame->width, frame->height,
                        (AVPixelFormat)frame->format, frame->width, frame->height,
                        AVPixelFormat.AV_PIX_FMT_BGRA, (int)SwsFlags.SWS_BILINEAR, null, null, null);
                    if (scaler == null) throw new OutOfMemoryException();
                    var pixels = new byte[checked(frame->width * frame->height * 4)];
                    fixed (byte* output = pixels)
                    {
                        byte_ptrArray4 planes = default;
                        int_array4 strides = default;
                        planes[0] = output;
                        strides[0] = frame->width * 4;
                        int rows = ffmpeg.sws_scale(scaler, frame->data, frame->linesize,
                                                   0, frame->height, planes, strides);
                        if (rows != frame->height) throw new InvalidDataException("Short pixel conversion.");
                    }
                    last = new VideoFrame(frame->width, frame->height, pixels, frame->best_effort_timestamp);
                    if (count == 1) firstFrame?.Invoke();
                }
                finally { ffmpeg.av_frame_unref(frame); }
            }
        }
    }

    public static object ProbeHardware()
    {
        AVBufferRef* device = null;
        try
        {
            int result = ffmpeg.av_hwdevice_ctx_create(&device, AVHWDeviceType.AV_HWDEVICE_TYPE_D3D11VA,
                                                       null, null, 0);
            return new { available = result >= 0, result,
                         note = "Device-context probe only; not a hardware decode result." };
        }
        finally { ffmpeg.av_buffer_unref(&device); }
    }

    private static void Check(int result)
    {
        if (result < 0) throw new InvalidDataException($"FFmpeg error {result}.");
    }
}
