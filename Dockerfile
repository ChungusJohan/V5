FROM node:22
USER root
WORKDIR /home/choreouser
COPY / /home/choreouser/
RUN apt update && apt upgrade -y
RUN npm i ws express@4.21.2 basic-auth dns2
RUN apt install curl -y
RUN apt install wget -y
RUN apt install python3 -y
RUN apt install unzip -y
RUN curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh && chmod +x agent.sh 
COPY . .
EXPOSE 7860
CMD ["node", "script.js"]

