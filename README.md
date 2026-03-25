# ONOL

**ONOL**은 로컬 네트워크의 패킷을 실시간으로 수집하고 분석하여 위협 탐지와 통계 정보를 제공하는 네트워크 분석 시스템입니다. 단순히 모든 트래픽을 기록하는 기존 방식에서 벗어나, 데이터의 문맥을 파악해 가치 있는 정보만을 선별함으로써 스토리지 효율과 분석 정합성을 동시에 확보했습니다.

대용량 트래픽이 쏟아지는 환경에서도 시스템의 실시간성을 유지하기 위해 수집(Collector)과 분석(Analyzer) 레이어를 Kafka로 물리적 분리했으며, Redis 파이프라이닝과 비동기 논블로킹 I/O를 활용해 데이터 파이프라인의 병목을 제거했습니다. 또한 헥사고날 아키텍처를 적용하여 인프라의 변화에도 비즈니스 로직의 순수성을 보존할 수 있는 유연한 구조를 지향합니다.

## Preview

<details>
<summary><strong>전체 대시보드</strong></summary>
<br>
<img width="2560" height="1279" alt="Image" src="https://github.com/user-attachments/assets/f7128c85-a4ca-4cf9-9718-7e57df04f6a2" />
</details>

<details>
<summary><strong>실시간 네트워크 처리량(PPS) 추이</strong></summary>
<br>
<img width="1843" height="372" alt="Image" src="https://github.com/user-attachments/assets/3d18ed66-f5d7-40b9-ad9e-9aa2961770e3">
</details>

<details>
<summary><strong>프로토콜별 트래픽 분포 및 점유율</strong></summary>
<br>
<img width="362" height="372" alt="Image" src="https://github.com/user-attachments/assets/6dc59f97-b4a9-4c2b-a4db-0de19a21f01b" />
</details>

<details>
<summary><strong>실시간 접속 로그 및 도메인(SNI) 식별 정보</strong></summary>
<br>
<img width="2213" height="486" alt="Image" src="https://github.com/user-attachments/assets/afeeba27-448e-4c69-ad82-8e57ea1168e2" />
</details>

<details>
<summary><strong>지리적 유입 경로 시각화 및 국가별 패킷 통계</strong></summary>
<br>
<img width="2213" height="600" alt="Image" src="https://github.com/user-attachments/assets/c4f1f023-1bbf-4009-99b8-a865d6d83433" />
</details>

## Key Features

  * **Context-Aware Smart Logging**: 모든 패킷을 저장하지 않고 연결 제어 패킷과 세션 초반 10개의 핵심 문맥만 선별 저장하여, **스토리지 점유율을 90% 이상 절감**하고 DB 쓰기 성능을 개선합니다.
  * **Bulk-Optimized Pipeline**: Redis Pipelining 및 Bulk 연산을 도입해 네트워크 RTT 부하를 최소화하고, **초당 처리량(TPS)을 6.7배 향상**시켜 8분 규모의 처리 지연을 해소했습니다.
  * **Atomic Threat Detection**: 외부 공격자의 포트 스캔 행위를 실시간으로 식별합니다. Redis Set 구조를 통해 오탐을 방지하며, 분석 파이프라인과 독립된 비동기 알림 체계로 즉각적인 대응을 지원합니다.
  * **Zero-Copy SNI Parser**: TLS Handshake의 Client Hello 영역을 바이트 단위로 직접 탐색하여, 트래픽 복호화 없이 접속 대상 도메인(SNI)을 실시간으로 추출합니다.
  * **Self-Sustaining Backpressure**: `CallerRunsPolicy`를 적용하여 DB 저장 부하가 임계치를 넘을 경우 컨슈머가 직접 처리하게 함으로써, **시스템 붕괴 리스크를 방지하고 처리 속도를 자생적으로 조절**합니다.

## System Architecture

데이터의 정합성과 효율적인 처리를 보장하기 위해 **이벤트 구동형 헥사고날 아키텍처**를 기반으로 설계되었습니다.

<img width="2712" height="3660" alt="Image" src="https://github.com/user-attachments/assets/53703a7f-78ab-4a9a-b63c-b7488797386f" />

### 수집과 분석의 물리적 분리 (Collector-Analyzer)

  * **Collector**: `Pcap4j` 기반의 수집기가 패킷을 캡처한 후 최소한의 노이즈 필터링을 거쳐 Kafka로 전송함으로써 수집 스레드의 부하를 최소화합니다.
  * **Analyzer**: Kafka 배치를 소비하여 위협 탐지 및 세션 추적을 수행합니다. 처리 실패 데이터는 에러 메시지와 함께 DLQ(Dead Letter Queue)로 격리하여 유실 없는 재처리 환경을 구축했습니다.

### 도메인 중심의 상태 관리

  * **TcpSessionTracker**: 패킷의 방향에 관계없이 동일한 Flow Key를 생성하고, Redis를 활용해 TCP 연결 상태를 실시간으로 관리하는 상태 머신 역할을 수행합니다.
  * **PortScanDetector**: 특정 IP로부터 유입되는 서로 다른 목적지 포트의 개수를 Redis Set을 통해 원자적으로 카운팅하여 수직적 포트 스캔 공격을 즉각 탐지합니다.

## Engineering Challenges

### Redis N+1 문제 해결을 통한 처리량 확보

초기 설계에서는 패킷당 개별적인 Redis RTT가 발생하여 대용량 트래픽 환경에서 실시간성이 무너지는 현상이 발생했습니다. 배치 처리 시 1,250ms가 소요되어 약 8분의 데이터 처리 지연이 발생했습니다.

  * **해결책**: **'Bulk Read → In-Memory 상태 전이 계산 → Bulk Write'** 패턴으로 로직을 리팩토링했습니다. `MultiGet`과 Redis Pipelining을 도입하여 수천 개의 명령을 단 한 번의 네트워크 통신으로 처리하도록 최적화했습니다.
  * **결과**: 배치 처리 시간을 **약 83% 단축**하고, TPS를 **6.7배(390 → 2,600)** 향상시켜 파이프라인의 실시간성을 확보했습니다.

### 스마트 로깅 정책을 통한 Elephant Flow 제어 및 스토리지 최적화

4K 영상 스트리밍 등 분석 가치가 낮은 대용량 UDP 트래픽이 무제한 저장되어 스토리지 낭비와 DB I/O 병목을 유발했습니다.

  * **해결책**: Redis Atomic Increment를 활용해 세션별 패킷 누적 수를 추적하고, **초반 10개 패킷 및 제어 패킷만 저장**하는 선별적 로깅 정책을 도입했습니다. DNS와 같은 필수 식별 패킷은 유지하되 단순 데이터 패킷은 과감히 폐기했습니다.
  * **결과**: 분석에 필요한 핵심 문맥은 100% 보존하면서 **스토리지 사용량을 90% 이상 절감**했으며, 처리 속도를 **9.8배 개선**했습니다.

### Redis Set 기반의 원자적 위협 탐지 로직 설계

외부 공격자가 시스템의 취약점을 탐색하기 위해 수행하는 포트 스캔 행위를 실시간으로 식별해야 했습니다. 단순히 패킷의 양을 측정하는 방식은 정상적인 다중 연결과 악의적인 스캔 행위를 구분하지 못해 탐지 정합성이 낮아지는 결함이 있었습니다.

* **해결책**: Redis의 **Set 자료구조**를 활용해 특정 IP가 접속한 목적지 포트를 중복 없이 수집하고, 5분 단위의 슬라이딩 윈도우 내에서 고유 포트 개수를 확인하는 로직을 구현했습니다. `SADD`와 `SCARD` 명령을 **Pipelining**으로 결합하여 원자적 카운팅을 수행하고 통신 오버헤드를 관리했습니다.
* **결과**: 위협 감지 시에도 분석 파이프라인의 성능을 유지하며 식별이 가능해졌으며, **이벤트 기반 아키텍처**를 통해 분석 로직과 알림 전파 로직(Discord)을 격리하여 시스템 안정성을 확보했습니다.

### 네트워크 환경 변화에 대응하는 Supervisor 루프 설계

물리 네트워크 인터페이스 변경이나 가상 인터페이스(Docker 등) 혼재 시 수집 프로세스가 중단되는 결함을 해결해야 했습니다.

  * **해결책**: 5초 주기로 시스템의 모든 장치를 검색하여 최적의 물리 인터페이스를 자동 식별하는 **Supervisor 루프**를 구현했습니다.
  * **결과**: 루프백이나 가상 장치를 제외한 실제 트래픽 장치를 우선 선택하며, 네트워크 단절이나 환경 변화 시에도 별도의 재시작 없이 **무중단 스위칭**이 가능한 안정성을 확보했습니다.

## Performance Metrics

벤치마킹 브랜치를 통해 측정한 최적화 전(Legacy)과 후(Optimized)의 성능 지표입니다.

| 측정 지표 | 최적화 전 (Legacy) | 최적화 후 (Optimized) | 개선 결과 |
| :--- | :--- | :--- | :--- |
| **평균 처리 시간 (Batch 500)** | \~1,250 ms | **\~220 ms** | **83.2% 단축** |
| **초당 처리량 (TPS)** | \~390 TPS | **\~2,600 TPS** | **6.7배 향상** |
| **스토리지 사용량 (Streaming)** | 100% 저장 | **\< 10% 저장** | **90% 이상 절감** |
| **시스템 지연 (Lag)** | 지속적 증가 (8분+) | **0초 (실시간 유지)** | **완전 해소** |

## Technical Stack

### Core & Infrastructure

  * **Java 21 & Spring Boot 3.3.2**: 가상 스레드 및 최신 Spring 생태계 활용
  * **Apache Kafka 3.7**: 수집/분석 모듈 간 물리적 분리 및 메시지 버퍼링
  * **Redis 7.2**: 실시간 세션 상태 관리 및 위협 탐지 카운터
  * **TimescaleDB (PostgreSQL 17)**: 시계열 패킷 로그 저장 및 최적화

### Packet Analysis

  * **Pcap4j 1.8.2**: Native 네트워크 인터페이스 제어 및 패킷 캡처
  * **Netty ByteBuf**: 바이트 조작 및 TLS SNI 직접 파싱
  * **MaxMind GeoIP2**: IP 기반 전 세계 국가 코드 해소

## Installation

1.  저장소를 복제합니다.

```bash
git clone https://github.com/tenoenc/onol.git
cd onol
```

2.  Docker Compose를 통해 인프라 서비스를 실행합니다.

```bash
docker-compose up -d
```

3.  Analyzer와 Collector 모듈을 실행합니다. 윈도우 환경에서는 Npcap 설치와 관리자 권한이 필요합니다.

## License

본 프로젝트는 MIT 라이선스를 따릅니다. 자세한 내용은 [LICENSE](./LICENSE) 파일을 참고해 주세요.
