FROM node:24-alpine AS build

WORKDIR /app
# Türkçe: pnpm 11'e sabitlendi (packageManager alanıyla uyumlu)
RUN npm install -g pnpm@11
# Türkçe: pnpm-workspace.yaml install'dan ÖNCE gelmeli — build script izinleri
# (dangerouslyAllowAllBuilds) orada tanımlı; yoksa ERR_PNPM_IGNORED_BUILDS olur.
COPY package.json pnpm-lock.yaml* pnpm-workspace.yaml* ./
# Türkçe: vendor/ ŞART — xlsx (SheetJS) depoya gömülü tarball'dan kurulur (file:vendor/...);
# kopyalanmazsa pnpm install ENOENT ile düşer (registry'de 0.20.3 YOK — npm bilinen bayat).
# NOT: pnpm 11.0.0 file:/URL tarball bağımlılıklarında lock 'resolution' alanına 'tarball:'
# yazmıyor → soğuk kurumda registry URL'i uydurup 404 düşüyor; lock'taki tarball: alanı
# BİLİNÇLİ elle tamamlanmıştır. --frozen-lockfile build'in lock'u yeniden yazmasını keser.
COPY vendor/ ./vendor/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build

FROM nginx:alpine
COPY --from=build /app/build/client /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
