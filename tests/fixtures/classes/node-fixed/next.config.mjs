/** @type {import("next").NextConfig} */
const nextConfig = {
  output: "standalone",
  async headers() {
    return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }] }];
  },
};

export default nextConfig;
