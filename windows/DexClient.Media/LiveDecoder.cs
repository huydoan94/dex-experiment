using System.Runtime.InteropServices;
using FFmpeg.AutoGen;

namespace DexClient.Media;

public sealed record LiveDecodeResult(long VideoFrames, long AudioFrames);

// Continuous custom AVIO. No fixture-sized byte/frame/time limits; each queue
// and individual decoded frame remains bounded. Callbacks never expose payloads
// to logs. Cancellation wakes the managed read before native resources are freed.
public static unsafe class LiveDecoder
{
    public static LiveDecodeResult Decode(Stream source, Action<VideoFrame> video,
                                           Action<byte[]> audio, CancellationToken cancellation, bool reuseVideoBuffers = false,
                                           Action<long?, byte[]>? timedAudio = null, Action<string, double>? measure = null)
    {
        using var input = new StreamingTsInput(source, cancellation);
        using var pool = reuseVideoBuffers ? new VideoBufferPool() : null;
        var handle = GCHandle.Alloc(input);
        avio_alloc_context_read_packet read = Read;
        AVIOInterruptCB_callback interrupt = Interrupt;
        var cancelHandle = GCHandle.Alloc(cancellation);
        AVFormatContext* format = null;
        AVIOContext* io = null;
        byte* buffer = null;
        AVCodecContext* vc = null;
        AVCodecContext* ac = null;
        AVPacket* packet = null;
        AVFrame* frame = null;
        SwsContext* scaler = null;
        SwrContext* resampler = null;
        AVDictionary* options = null;
        AVDictionary** probe = stackalloc AVDictionary*[4];
        for (int i = 0; i < 4; i++) probe[i] = null;
        AVChannelLayout stereo = default;
        long videoFrames = 0, audioFrames = 0;
        AVRational videoTimeBase = default, audioTimeBase = default;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            buffer = (byte*)ffmpeg.av_malloc(32768);
            if (buffer == null) throw new OutOfMemoryException();
            io = ffmpeg.avio_alloc_context(buffer, 32768, 0, (void*)GCHandle.ToIntPtr(handle), read, default, default);
            if (io == null) throw new OutOfMemoryException();
            io->seekable = 0;
            format = ffmpeg.avformat_alloc_context();
            if (format == null) throw new OutOfMemoryException();
            format->pb = io;
            format->flags |= ffmpeg.AVFMT_FLAG_CUSTOM_IO;
            format->interrupt_callback = new AVIOInterruptCB { callback = interrupt, opaque = (void*)GCHandle.ToIntPtr(cancelHandle) };
            format->max_streams = 4;
            format->probesize = 1000000;
            format->max_analyze_duration = 1000000;
            Check(ffmpeg.av_dict_set(&options, "protocol_whitelist", "", 0));
            Check(ffmpeg.avformat_open_input(&format, null, ffmpeg.av_find_input_format("mpegts"), &options));
            for (int i = 0; i < 4; i++) Check(ffmpeg.av_dict_set(probe + i, "max_pixels", "2073600", 0));
            Check(ffmpeg.avformat_find_stream_info(format, probe));
            if (format->nb_streams > 4) throw new InvalidDataException("Too many media streams.");
            AVCodec* codec = null;
            int vi = ffmpeg.av_find_best_stream(format, AVMediaType.AVMEDIA_TYPE_VIDEO, -1, -1, &codec, 0);
            Check(vi);
            vc = Open(format->streams[vi], codec);
            videoTimeBase = format->streams[vi]->time_base;
            int ai = ffmpeg.av_find_best_stream(format, AVMediaType.AVMEDIA_TYPE_AUDIO, -1, -1, &codec, 0);
            if (ai >= 0)
            {
                ac = Open(format->streams[ai], codec);
                audioTimeBase = format->streams[ai]->time_base;
                if (ac->sample_rate <= 0 || ac->sample_rate > 192000 || ac->ch_layout.nb_channels > 8)
                    throw new InvalidDataException("Audio format outside bounds.");
                ffmpeg.av_channel_layout_default(&stereo, 2);
                SwrContext* allocated = null;
                Check(ffmpeg.swr_alloc_set_opts2(&allocated, &stereo, AVSampleFormat.AV_SAMPLE_FMT_FLT, 48000,
                                                &ac->ch_layout, ac->sample_fmt, ac->sample_rate, 0, null));
                resampler = allocated;
                Check(ffmpeg.swr_init(resampler));
            }
            packet = ffmpeg.av_packet_alloc();
            frame = ffmpeg.av_frame_alloc();
            if (packet == null || frame == null) throw new OutOfMemoryException();
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                int status = ffmpeg.av_read_frame(format, packet);
                if (status == ffmpeg.AVERROR_EOF) break;
                Check(status);
                try
                {
                    var context = packet->stream_index == vi ? vc : packet->stream_index == ai ? ac : null;
                    if (context == null) continue;
                    long sendingAt = System.Diagnostics.Stopwatch.GetTimestamp();
                    int sent = ffmpeg.avcodec_send_packet(context, packet);
                    if (sent == ffmpeg.AVERROR(ffmpeg.EAGAIN)) { Drain(context); sent = ffmpeg.avcodec_send_packet(context, packet); }
                    Check(sent);
                    measure?.Invoke("codecSend", System.Diagnostics.Stopwatch.GetElapsedTime(sendingAt).TotalMilliseconds);
                    Drain(context);
                }
                finally { ffmpeg.av_packet_unref(packet); }
            }
            Check(ffmpeg.avcodec_send_packet(vc, null)); Drain(vc);
            if (ac != null) { Check(ffmpeg.avcodec_send_packet(ac, null)); Drain(ac); }
            cancellation.ThrowIfCancellationRequested();
            if (input.Error != null) throw new IOException("Media transport failed.", input.Error);
            if (videoFrames == 0) throw new InvalidDataException("No decoded picture.");
            return new(videoFrames, audioFrames);
        }
        catch (Exception) when (cancellation.IsCancellationRequested) { throw new OperationCanceledException(cancellation); }
        finally
        {
            var toResample = resampler; ffmpeg.swr_free(&toResample);
            ffmpeg.av_channel_layout_uninit(&stereo);
            ffmpeg.sws_freeContext(scaler);
            var toFree = frame; ffmpeg.av_frame_free(&toFree);
            ffmpeg.av_packet_free(&packet);
            var videoContext = vc; ffmpeg.avcodec_free_context(&videoContext);
            var audioContext = ac; ffmpeg.avcodec_free_context(&audioContext);
            ffmpeg.avformat_close_input(&format);
            if (io != null) { ffmpeg.av_free(io->buffer); io->buffer = null; ffmpeg.avio_context_free(&io); }
            else ffmpeg.av_free(buffer);
            ffmpeg.av_dict_free(&options);
            for (int i = 0; i < 4; i++) ffmpeg.av_dict_free(probe + i);
            GC.KeepAlive(read); GC.KeepAlive(interrupt);
            handle.Free(); cancelHandle.Free();
        }
        static long? Timestamp(AVFrame* f, AVRational basis) => f->best_effort_timestamp == ffmpeg.AV_NOPTS_VALUE ? null :
            ffmpeg.av_rescale_q(f->best_effort_timestamp, basis, new AVRational { num = 1, den = 1000000 });
        void Drain(AVCodecContext* context)
        {
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                long receivingAt = System.Diagnostics.Stopwatch.GetTimestamp();
                int got = ffmpeg.avcodec_receive_frame(context, frame);
                measure?.Invoke("codecReceive", System.Diagnostics.Stopwatch.GetElapsedTime(receivingAt).TotalMilliseconds);
                if (got == ffmpeg.AVERROR(ffmpeg.EAGAIN) || got == ffmpeg.AVERROR_EOF) return;
                Check(got);
                try
                {
                    if (context == vc)
                    {
                        if (frame->width <= 0 || frame->height <= 0 || frame->width > 1920 || frame->height > 1080)
                            throw new InvalidDataException("Video exceeds 1080p bounds.");
                        long convertingAt = System.Diagnostics.Stopwatch.GetTimestamp();
                        scaler = ffmpeg.sws_getCachedContext(scaler, frame->width, frame->height, (AVPixelFormat)frame->format,
                            frame->width, frame->height, AVPixelFormat.AV_PIX_FMT_BGRA, (int)SwsFlags.SWS_BILINEAR, null, null, null);
                        if (scaler == null) throw new OutOfMemoryException();
                        int bytes = checked(frame->width * frame->height * 4);
                        var pixels = pool?.Rent(bytes) ?? new byte[bytes];
                        var picture = new VideoFrame(frame->width, frame->height, pixels, frame->best_effort_timestamp)
                        { PresentationMicroseconds = Timestamp(frame, videoTimeBase), Recycle = pool == null ? null : pool.Return };
                        try
                        {
                        fixed (byte* output = pixels)
                        {
                            byte_ptrArray4 planes = default; int_array4 strides = default;
                            planes[0] = output; strides[0] = frame->width * 4;
                            if (ffmpeg.sws_scale(scaler, frame->data, frame->linesize, 0, frame->height, planes, strides) != frame->height)
                                throw new InvalidDataException("Short video conversion.");
                        }
                        measure?.Invoke("conversion", System.Diagnostics.Stopwatch.GetElapsedTime(convertingAt).TotalMilliseconds);
                        input.Streaming();
                        videoFrames++;
                        video(picture);
                        }
                        catch { picture.Dispose(); throw; }
                    }
                    else
                    {
                        if (frame->nb_samples <= 0 || frame->nb_samples > 8192) throw new InvalidDataException("Audio frame too large.");
                        long needed = (ffmpeg.swr_get_delay(resampler, ac->sample_rate) + frame->nb_samples) * 48000 / ac->sample_rate + 1;
                        if (needed > 65536) throw new InvalidDataException("Audio resample queue too large.");
                        var pcm = new byte[checked((int)needed * 8)];
                        fixed (byte* output = pcm)
                        {
                            byte* target = output;
                            int converted = ffmpeg.swr_convert(resampler, &target, (int)needed, frame->extended_data, frame->nb_samples);
                            Check(converted); Array.Resize(ref pcm, converted * 8);
                        }
                        audioFrames++;
                        if (timedAudio != null) timedAudio(Timestamp(frame, audioTimeBase), pcm);
                        else audio(pcm);
                    }
                }
                finally { ffmpeg.av_frame_unref(frame); }
            }
        }
    }
    private static AVCodecContext* Open(AVStream* stream, AVCodec* codec)
    {
        var context = ffmpeg.avcodec_alloc_context3(codec);
        if (context == null) throw new OutOfMemoryException();
        try
        {
            Check(ffmpeg.avcodec_parameters_to_context(context, stream->codecpar));
            context->max_pixels = 1920 * 1080;
            context->thread_count = codec->type == AVMediaType.AVMEDIA_TYPE_VIDEO ? Math.Clamp(Environment.ProcessorCount, 1, 4) : 1;
            context->thread_type = ffmpeg.FF_THREAD_SLICE;
            Check(ffmpeg.avcodec_open2(context, codec, null));
            return context;
        }
        catch { ffmpeg.avcodec_free_context(&context); throw; }
    }
    private static int Read(void* opaque, byte* bytes, int size)
    {
        try { return ((StreamingTsInput)GCHandle.FromIntPtr((nint)opaque).Target!).ReadNative(bytes, size); }
        catch { return ffmpeg.AVERROR_EXIT; }
    }
    private static int Interrupt(void* opaque)
    {
        try { return ((CancellationToken)GCHandle.FromIntPtr((nint)opaque).Target!).IsCancellationRequested ? 1 : 0; }
        catch { return 1; }
    }
    private static void Check(int status) { if (status < 0) throw new InvalidDataException($"Media decode error {status}."); }
}
