using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class KKuTuLiteServer
{
    private static readonly List<Stream> SseStreams = new List<Stream>();
    private static readonly object LockObj = new object();
    private static string RootDir;

    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        int port = 8080;
        if (args.Length > 0) int.TryParse(args[0], out port);

        RootDir = AppDomain.CurrentDomain.BaseDirectory;

        TcpListener listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        Console.WriteLine("============================================================");
        Console.WriteLine("  🎮 끄투 LITE (KKuTu Custom) 실시간 로컬 서버가 시작되었습니다!");
        Console.WriteLine("  👉 내 PC 접속 주소 : http://localhost:" + port);
        foreach (var ip in GetLocalIPs())
        {
            Console.WriteLine("  👉 같은 공유기(LAN) 친구 접속 주소 : http://" + ip + ":" + port);
        }
        Console.WriteLine("============================================================");

        if (args.Length < 2 || args[1] != "--no-browser")
        {
            try
            {
                System.Diagnostics.Process.Start("http://localhost:" + port);
            }
            catch { }
        }

        while (true)
        {
            try
            {
                TcpClient client = listener.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(HandleClient, client);
            }
            catch { }
        }
    }

    private static IEnumerable<string> GetLocalIPs()
    {
        var list = new List<string>();
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    list.Add(ip.ToString());
                }
            }
        }
        catch { }
        return list;
    }

    private static string ReadAsciiLine(Stream stream)
    {
        List<byte> bytes = new List<byte>();
        while (true)
        {
            int b = stream.ReadByte();
            if (b == -1)
            {
                if (bytes.Count == 0) return null;
                break;
            }
            if (b == '\n') break;
            if (b != '\r') bytes.Add((byte)b);
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    private static void HandleClient(object obj)
    {
        TcpClient client = (TcpClient)obj;
        try
        {
            NetworkStream stream = client.GetStream();

            string requestLine = ReadAsciiLine(stream);
            if (string.IsNullOrEmpty(requestLine))
            {
                client.Close();
                return;
            }

            string[] parts = requestLine.Split(' ');
            if (parts.Length < 2)
            {
                client.Close();
                return;
            }

            string method = parts[0];
            string rawPath = parts[1];
            string path = rawPath.Split('?')[0];

            int contentLength = 0;
            string line;
            while (!string.IsNullOrEmpty(line = ReadAsciiLine(stream)))
            {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                {
                    int.TryParse(line.Substring(15).Trim(), out contentLength);
                }
            }

            // 1) SSE 실시간 이벤트 스트림
            if (method == "GET" && path == "/api/events")
            {
                string sseHeader = "HTTP/1.1 200 OK\r\n" +
                                   "Content-Type: text/event-stream; charset=utf-8\r\n" +
                                   "Cache-Control: no-cache\r\n" +
                                   "Connection: keep-alive\r\n" +
                                   "Access-Control-Allow-Origin: *\r\n\r\n" +
                                   ": connected\n\n";
                byte[] hb = Encoding.UTF8.GetBytes(sseHeader);
                stream.Write(hb, 0, hb.Length);
                stream.Flush();

                lock (LockObj)
                {
                    SseStreams.Add(stream);
                }

                byte[] pingBytes = Encoding.UTF8.GetBytes(": ping\n\n");
                while (client.Connected)
                {
                    Thread.Sleep(15000);
                    try
                    {
                        lock (LockObj)
                        {
                            stream.Write(pingBytes, 0, pingBytes.Length);
                            stream.Flush();
                        }
                    }
                    catch
                    {
                        break;
                    }
                }

                lock (LockObj)
                {
                    SseStreams.Remove(stream);
                }
                client.Close();
                return;
            }

            // 2) 실시간 브로드캐스트 메시지 수신 (POST /api/send)
            if (method == "POST" && path == "/api/send")
            {
                byte[] buf = new byte[contentLength];
                int read = 0;
                while (read < contentLength)
                {
                    int r = stream.Read(buf, read, contentLength - read);
                    if (r <= 0) break;
                    read += r;
                }
                string body = Encoding.UTF8.GetString(buf, 0, read);

                BroadcastSse(body);

                byte[] okBytes = Encoding.UTF8.GetBytes("{\"ok\":true}");
                WriteHttpResponse(stream, "200 OK", "application/json; charset=utf-8", okBytes);
                client.Close();
                return;
            }

            // 3) 정적 파일 서빙
            if (path == "/") path = "/index.html";
            string relPath = path.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
            string fullPath = Path.GetFullPath(Path.Combine(RootDir, relPath));

            if (!fullPath.StartsWith(RootDir, StringComparison.OrdinalIgnoreCase) || !File.Exists(fullPath))
            {
                byte[] notFound = Encoding.UTF8.GetBytes("404 Not Found");
                WriteHttpResponse(stream, "404 Not Found", "text/plain; charset=utf-8", notFound);
                client.Close();
                return;
            }

            byte[] fileBytes = File.ReadAllBytes(fullPath);
            string contentType = GetContentType(fullPath);
            WriteHttpResponse(stream, "200 OK", contentType, fileBytes);
            client.Close();
        }
        catch
        {
            try { client.Close(); } catch { }
        }
    }

    private static void BroadcastSse(string json)
    {
        string clean = json.Replace("\r", "").Replace("\n", "");
        byte[] payload = Encoding.UTF8.GetBytes("data: " + clean + "\n\n");
        lock (LockObj)
        {
            for (int i = SseStreams.Count - 1; i >= 0; i--)
            {
                try
                {
                    SseStreams[i].Write(payload, 0, payload.Length);
                    SseStreams[i].Flush();
                }
                catch
                {
                    SseStreams.RemoveAt(i);
                }
            }
        }
    }

    private static void WriteHttpResponse(Stream stream, string status, string contentType, byte[] body)
    {
        string header = "HTTP/1.1 " + status + "\r\n" +
                        "Content-Type: " + contentType + "\r\n" +
                        "Content-Length: " + body.Length + "\r\n" +
                        "Cache-Control: no-cache\r\n" +
                        "Connection: close\r\n\r\n";
        byte[] headerBytes = Encoding.UTF8.GetBytes(header);
        stream.Write(headerBytes, 0, headerBytes.Length);
        stream.Write(body, 0, body.Length);
        stream.Flush();
    }

    private static string GetContentType(string filePath)
    {
        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext == ".html") return "text/html; charset=utf-8";
        if (ext == ".css") return "text/css; charset=utf-8";
        if (ext == ".js") return "application/javascript; charset=utf-8";
        if (ext == ".json") return "application/json; charset=utf-8";
        if (ext == ".svg") return "image/svg+xml";
        if (ext == ".png") return "image/png";
        return "application/octet-stream";
    }
}
