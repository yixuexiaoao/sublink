const { defineConfig } = require('@vue/cli-service')
const fs = require('fs')
const path = require('path')
// 版本号统一读取仓库根目录 VERSION 文件
process.env.VUE_APP_VER = fs.readFileSync(path.resolve(__dirname, '../VERSION'), 'utf-8').trim()
module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        pathRewrite: {
          '^/api': '' // 重写路径
        }
      }
    }
  },
  publicPath: process.env.NODE_ENV === 'development' ? '/' : '../static/'
})
