params:
  nr_thread: [1, 4]
  test: [read, write, rw]
  size: [4KB, 1MB]
end

#include test-common.msh

echo "testing with params: nr_thread=$nr_thread test=$test size=$size depth=$depth"
