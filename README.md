# cve数据分析
## 目的
分析nvd和cve的漏洞数据

## 环境搭建
```shell
# Clickhouse
docker run --rm -d -p 8123:8123 \
    --name analyze-clickhouse-server \
    -e CLICKHOUSE_DB=analyze_ck_db \
    -e CLICKHOUSE_USER=username_cyberkl \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    -e CLICKHOUSE_PASSWORD=password_cyberkl \
    --ulimit nofile=262144:262144 clickhouse

# Superset
git clone https://github.com/apache/superset
cd superset
echo "clickhouse-connect" > ./docker/requirements-local.txt
echo "MAPBOX_API_KEY=<INSERT>" > docker/.env-non-dev

docker compose -f docker-compose-image-tag.yml up

# http://localhost:8088 admin/admin
```

## TodoList
- [X] 下载nvd
- [X] 下载cve
- [ ] 解析nvd，转成struct
- [X] 解析cve，转成struct
- [X] cve入库ck
- [ ] nvd入库ck
