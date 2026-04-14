️ 注意事项

1. wrangler.toml 无法在 Pages 中使用，兼容性标志必须在 Cloudflare Dashboard 的 Pages 项目设置中手动开启：
   · 进入项目 → Settings → Functions → Compatibility Flags
   · 添加 nodejs_compat
2. Pages 函数文件位置：将 _worker.js 放在项目根目录的 /functions 文件夹下，或直接命名为 /functions/[[path]].js 以捕获所有路由。
