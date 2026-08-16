# Capture container — dumpcap only, minimum privilege.
#
# Build:
#   docker build -t cyber-surakshya/capture:latest docker/capture
#
# Run (Linux hosts only — see ingestion/capture/backends/docker_dumpcap.py for
# why --net=host is meaningless on Docker Desktop):
#   docker run -d --name cs-capture \
#     --net host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
#     --user pcap --read-only --tmpfs /tmp \
#     -v "$PWD/captures:/captures" \
#     cyber-surakshya/capture:latest \
#     -i eth0 -s 96 -b duration:60 -b files:120 -w /captures/cs.pcap -q

FROM alpine:3.20

# tshark pulls in dumpcap, which is the only binary this image runs. The
# Wireshark GUI and its dissector stack are deliberately absent — a capture
# container should not contain a protocol parser it never invokes.
RUN apk add --no-cache libcap tshark \
    && rm -f /usr/bin/tshark /usr/bin/editcap /usr/bin/mergecap /usr/bin/text2pcap \
    && adduser -D -H -s /sbin/nologin pcap \
    # dumpcap keeps only the two capabilities it needs and drops the rest as
    # soon as the capture socket is open.
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap \
    && chmod 750 /usr/bin/dumpcap \
    && chown root:pcap /usr/bin/dumpcap

# Written to by the capture; mounted from the host.
RUN mkdir -p /captures && chown pcap:pcap /captures
VOLUME ["/captures"]

USER pcap

# No shell form: the container runs dumpcap and nothing else, so a compromised
# argument cannot become a shell command.
ENTRYPOINT ["/usr/bin/dumpcap"]
CMD ["-v"]
