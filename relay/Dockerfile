# The relay is pure Node built-ins — no npm packages, nothing to install.
FROM node:20-alpine
WORKDIR /app
COPY server.js ./
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
CMD ["node", "server.js"]
