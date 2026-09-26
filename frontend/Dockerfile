FROM node:24-alpine AS build

WORKDIR /app
# Türkçe: pnpm 11'e sabitlendi (packageManager alanıyla uyumlu)
RUN npm install -g pnpm@11
# Türkçe: pnpm-workspace.yaml install'dan ÖNCE gelmeli — build script izinleri
# (dangerouslyAllowAllBuilds) orada tanımlı; yoksa ERR_PNPM_IGNORED_BUILDS olur.
COPY package.json pnpm-lock.yaml* pnpm-workspace.yaml* ./
RUN pnpm install
COPY . .
RUN pnpm run build

FROM nginx:alpine
COPY --from=build /app/build/client /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
