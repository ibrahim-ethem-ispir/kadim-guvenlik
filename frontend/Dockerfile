FROM node:24-alpine AS build

WORKDIR /app
# Türkçe: pnpm 11'e sabitlendi (packageManager alanıyla uyumlu)
RUN npm install -g pnpm@11
# Türkçe: pnpm-workspace.yaml install'dan ÖNCE gelmeli — build script izinleri
# (dangerouslyAllowAllBuilds) orada tanımlı; yoksa ERR_PNPM_IGNORED_BUILDS olur.
COPY package.json pnpm-lock.yaml* pnpm-workspace.yaml* ./
# Türkçe: vendor/ ŞART — xlsx (SheetJS 0.20.3) depoya gömülü DİZİN bağımlılığıdır
# (file:vendor/xlsx). Neden dizin: (1) npm registry'de xlsx bilinen bayat (0.18.5),
# URL/tarball bağımlılıklarında pnpm 11.0.0 soğuk kurumda lock'tan tarball kaynağı
# türetemeyip uydurma registry URL'ine 404 düşüyor; (2) dizin bağımlılığı fetch mantığına
# dokunmaz — lock yeniden yazılsa da bozulmaz. Kopyalanmazsa install ENOENT ile düşer.
COPY vendor/ ./vendor/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build

FROM nginx:alpine
COPY --from=build /app/build/client /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
