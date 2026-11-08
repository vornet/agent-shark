FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source
COPY . .
RUN dotnet restore --locked-mode && dotnet publish src/AgentShark.Server -c Release --no-restore -o /out

FROM build AS test
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
RUN dotnet test -c Release --no-restore --logger "console;verbosity=normal"
ENV AGENTSHARK_TEST_NATIVE=1
ENTRYPOINT ["dotnet", "test", "-c", "Release", "--no-build", "--no-restore", "--logger", "console;verbosity=normal"]

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out .
RUN mkdir -p /data && chown "$APP_UID:$APP_UID" /data
USER $APP_UID
ENV AGENTSHARK_DATA_DIRECTORY=/data
VOLUME /data
ENTRYPOINT ["dotnet", "AgentShark.Server.dll"]
