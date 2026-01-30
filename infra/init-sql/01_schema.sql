-- 1. TimescaleDB 확장 활성화
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- 2. 패킷 원본 테이블 (스키마 + SNI 컬럼)
CREATE TABLE raw_packet_log (
    time            TIMESTAMPTZ NOT NULL,
    src_ip          INET,
    dst_ip          INET,
    src_port        INT,
    dst_port        INT,
    protocol        SMALLINT,
    tcp_flags       INT DEFAULT 0,
    payload_len     INT,
    payload         BYTEA,
    country_code    VARCHAR(10),
    domain_name     TEXT  -- HTTPS 분석을 위한 SNI 컬럼
);

-- 3. 하이퍼테이블 변환 (1일 단위 파티셔닝)
SELECT create_hypertable('raw_packet_log', 'time', chunk_time_interval => INTERVAL '1 day');

-- 4. 인덱스 (조회 최적화)
CREATE INDEX ix_raw_time_src ON raw_packet_log (time DESC, src_ip);
CREATE INDEX ix_raw_time_dst ON raw_packet_log (time DESC, dst_ip);

-- 5. 데이터 자동 관리 정책
-- 압축 정책 추가 전, 테이블 압축 속성 활성화
ALTER TABLE raw_packet_log SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'protocol, src_ip, dst_ip' -- 압축 효율을 위한 세그먼트 기준
);

-- 1시간 지난 데이터는 압축, 7일 지난 데이터는 삭제
SELECT add_compression_policy('raw_packet_log', INTERVAL '1 hours');
SELECT add_retention_policy('raw_packet_log', INTERVAL '7 days');

-- 6. 시스템 관리 테이블
CREATE TABLE system_heartbeat (
    last_alive_time TIMESTAMPTZ PRIMARY KEY,
    app_version     VARCHAR(20),
    status          VARCHAR(20)
);

-- 7. 연속 집계 뷰
-- 1시간 단위 통계를 DB가 자동으로 계산하도록 설정
CREATE MATERIALIZED VIEW traffic_stats_hourly_mat
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', time) as bucket,
       src_ip,
       dst_ip,
       count(*) as total_packets,
       sum(payload_len) as total_bytes
FROM raw_packet_log
GROUP BY bucket, src_ip, dst_ip;

-- 뷰 갱신 스케줄 (30분 마다)
SELECT add_continuous_aggregate_policy('traffic_stats_hourly_mat',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '30 minutes');