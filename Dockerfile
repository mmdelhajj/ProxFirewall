FROM node:20-alpine

WORKDIR /app
COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY admin-v2.html ./
COPY customer-portal.html ./
COPY box-agent ./box-agent
COPY cloud-modules ./cloud-modules
COPY oui-table.json ./
COPY dbip-country-ipv4.csv ./
COPY qrcode.min.js ./

EXPOSE 8080
CMD ["node", "server.js"]
