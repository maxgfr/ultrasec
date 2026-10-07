/** @type {import("next").NextConfig} */
const nextConfig = {
  output: "standalone",
  experimental: { serverActions: { allowedOrigins: ["app.example.com"] } },
  async headers() {
    return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }] }];
  },
};

export default nextConfig;
