- 금투사 연계 가이드용 소스

* 테스트용 포트: 16001

[build]

  make

빌드 마지막에 키생성과 인증서 생성을 위한 비밀번호 입력이 필요함

[clean]

  make clean

  make certclean
  

# 참고용으로만 사용하세요. 본래 read/write 부분에 대해서는 select를 사용해서 non-blocking처리하는 것이 보통이나,
  본 소스는 accept/connect 부분까지 select 범위에 포함
