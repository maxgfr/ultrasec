/** @type {import("next").NextConfig} */
const nextConfig = {
  output: "standalone",
  async redirects() {
    return [{ source: "/old", destination: "/new", permanent: true }];
  },
};

export default nextConfig;
