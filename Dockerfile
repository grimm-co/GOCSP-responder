FROM scratch
ADD ./build/gocsp /
CMD ["/gocsp"]
