#ifndef BOUNDED_OUTPUT_H_INCLUDED
#define BOUNDED_OUTPUT_H_INCLUDED

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

class BoundedOutputExceeded final : public std::length_error {
public:
  BoundedOutputExceeded()
      : std::length_error("generated output exceeds its hard byte limit") {}
};

inline size_t checkedBoundedOutputSize(size_t current, size_t additional,
                                       size_t limit) {
  if (additional > limit || current > limit - additional)
    throw BoundedOutputExceeded();
  return current + additional;
}

class BoundedOutputSink {
public:
  using Ch = char;

  explicit BoundedOutputSink(
      size_t limit = std::numeric_limits<size_t>::max())
      : limit_(limit) {}

  size_t limit() const noexcept { return limit_; }
  size_t size() const noexcept { return size_; }
  size_t remaining() const noexcept { return limit_ - size_; }
  bool empty() const noexcept { return size_ == 0; }

  void reserve(size_t requested) {
    if (requested > limit_)
      throw BoundedOutputExceeded();
    while (allocated_capacity_ < requested)
      allocateChunk(requested - allocated_capacity_);
  }

  void append(const char *data, size_t size) {
    checkedBoundedOutputSize(size_, size, limit_);
    size_t offset = 0;
    while (offset < size) {
      if (chunks_.empty() || chunks_.back().used == chunks_.back().capacity)
        allocateChunk(size - offset);
      Chunk &chunk = chunks_.back();
      const size_t writable =
          std::min(size - offset, chunk.capacity - chunk.used);
      std::copy_n(data + offset, writable, chunk.data.get() + chunk.used);
      chunk.used += writable;
      size_ += writable;
      offset += writable;
    }
  }

  void append(std::string_view value) { append(value.data(), value.size()); }

  void append(char value) {
    append(&value, 1);
  }

  void prepend(std::string_view value) {
    if (!empty())
      throw std::logic_error(
          "bounded prepend is supported only before output starts");
    append(value);
  }

  void truncate(size_t requested_size) noexcept {
    if (requested_size >= size_)
      return;
    size_t remove = size_ - requested_size;
    for (auto iter = chunks_.rbegin(); iter != chunks_.rend() && remove != 0;
         ++iter) {
      const size_t removed = std::min(remove, iter->used);
      iter->used -= removed;
      remove -= removed;
    }
    size_ = requested_size;
  }

  // RapidJSON OutputStream interface. Put() must throw before std::string can
  // grow, so Writer/PrettyWriter cannot materialize limit+1 bytes.
  void Put(char value) { append(value); }

  void PutN(char value, size_t count) {
    checkedBoundedOutputSize(size_, count, limit_);
    while (count != 0) {
      if (chunks_.empty() || chunks_.back().used == chunks_.back().capacity)
        allocateChunk(count);
      Chunk &chunk = chunks_.back();
      const size_t writable = std::min(count, chunk.capacity - chunk.used);
      std::fill_n(chunk.data.get() + chunk.used, writable, value);
      chunk.used += writable;
      size_ += writable;
      count -= writable;
    }
  }

  void Flush() noexcept {}

  size_t GetSize() const noexcept { return size_; }

  size_t allocatedCapacity() const noexcept { return allocated_capacity_; }

  std::string release() {
    // Construct the ABI string at its exact logical size, then copy from the
    // independently bounded chunks. The force_max caller gives staging and ABI
    // strings one half each so both can coexist during this conversion.
    std::string result(size_, '\0');
    size_t offset = 0;
    for (const Chunk &chunk : chunks_) {
      std::copy_n(chunk.data.get(), chunk.used, result.data() + offset);
      offset += chunk.used;
    }
    const size_t inline_capacity = std::string().capacity();
    if (result.capacity() > limit_ && result.capacity() > inline_capacity)
      throw BoundedOutputExceeded();
    chunks_.clear();
    allocated_capacity_ = 0;
    size_ = 0;
    return result;
  }

private:
  struct Chunk {
    std::unique_ptr<char[]> data;
    size_t capacity = 0;
    size_t used = 0;
  };

  void allocateChunk(size_t minimum) {
    constexpr size_t kChunkBytes = 64 * 1024;
    if (allocated_capacity_ >= limit_)
      throw BoundedOutputExceeded();
    const size_t available = limit_ - allocated_capacity_;
    const size_t requested =
        std::min(available, std::max(minimum, std::min(kChunkBytes, available)));
    if (requested == 0)
      throw BoundedOutputExceeded();
    Chunk chunk;
    chunk.data = std::make_unique_for_overwrite<char[]>(requested);
    chunk.capacity = requested;
    chunks_.push_back(std::move(chunk));
    allocated_capacity_ += requested;
  }

  size_t limit_;
  size_t size_ = 0;
  size_t allocated_capacity_ = 0;
  std::vector<Chunk> chunks_;
};

class BoundedOutputStreambuf final : public std::streambuf {
public:
  explicit BoundedOutputStreambuf(BoundedOutputSink &sink) : sink_(sink) {}

protected:
  int_type overflow(int_type value) override {
    if (traits_type::eq_int_type(value, traits_type::eof()))
      return traits_type::not_eof(value);
    sink_.append(traits_type::to_char_type(value));
    return value;
  }

  std::streamsize xsputn(const char *data, std::streamsize size) override {
    if (size <= 0)
      return 0;
    sink_.append(data, static_cast<size_t>(size));
    return size;
  }

private:
  BoundedOutputSink &sink_;
};

class BoundedOutputStreamStorage {
protected:
  explicit BoundedOutputStreamStorage(BoundedOutputSink &sink)
      : buffer_(sink) {}

  BoundedOutputStreambuf buffer_;
};

class BoundedOutputStream final : private BoundedOutputStreamStorage,
                                  public std::ostream {
public:
  explicit BoundedOutputStream(BoundedOutputSink &sink)
      : BoundedOutputStreamStorage(sink), std::ostream(&buffer_) {
    // By default iostream swallows streambuf exceptions and only sets badbit.
    // Re-throw them so a capacity breach remains distinguishable from an
    // ordinary serializer failure.
    exceptions(std::ios::badbit | std::ios::failbit);
  }
};

class Base64OutputSink {
public:
  using Ch = char;

  struct Checkpoint {
    size_t output_size = 0;
    unsigned char tail[2]{};
    size_t tail_size = 0;
  };

  explicit Base64OutputSink(size_t max_output_bytes,
                            bool url_safe = false,
                            bool padding = true)
      : output_(max_output_bytes), url_safe_(url_safe), padding_(padding) {}

  void append(const char *data, size_t size) {
    for (size_t index = 0; index < size; ++index) {
      tail_[tail_size_++] = static_cast<unsigned char>(data[index]);
      if (tail_size_ == 3) {
        emit(tail_[0], tail_[1], tail_[2], 3);
        tail_size_ = 0;
      }
    }
  }

  void append(std::string_view value) { append(value.data(), value.size()); }
  void Put(char value) { append(&value, 1); }
  void Flush() noexcept {}

  Checkpoint checkpoint() const noexcept {
    Checkpoint result;
    result.output_size = output_.size();
    result.tail_size = tail_size_;
    std::copy_n(tail_, tail_size_, result.tail);
    return result;
  }

  void rollback(const Checkpoint &checkpoint) noexcept {
    output_.truncate(checkpoint.output_size);
    tail_size_ = checkpoint.tail_size;
    std::copy_n(checkpoint.tail, tail_size_, tail_);
  }

  void prepend(std::string_view value) { output_.prepend(value); }

  std::string release() {
    if (tail_size_ != 0) {
      const unsigned char second = tail_size_ > 1 ? tail_[1] : 0;
      emit(tail_[0], second, 0, tail_size_);
      tail_size_ = 0;
    }
    return output_.release();
  }

private:
  char alphabet(size_t index) const noexcept {
    static constexpr char standard[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static constexpr char urlsafe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return (url_safe_ ? urlsafe : standard)[index];
  }

  void emit(unsigned char first, unsigned char second, unsigned char third,
            size_t available) {
    char encoded[4] = {
        alphabet((first & 0xfc) >> 2),
        alphabet(((first & 0x03) << 4) | ((second & 0xf0) >> 4)),
        alphabet(((second & 0x0f) << 2) | ((third & 0xc0) >> 6)),
        alphabet(third & 0x3f),
    };
    size_t encoded_size = 4;
    if (available < 3) {
      if (padding_) {
        encoded[3] = '=';
        if (available < 2)
          encoded[2] = '=';
      } else {
        encoded_size = available + 1;
      }
    }
    output_.append(encoded, encoded_size);
  }

  BoundedOutputSink output_;
  bool url_safe_ = false;
  bool padding_ = true;
  unsigned char tail_[3]{};
  size_t tail_size_ = 0;
};

inline std::string boundedConcatWithRetained(std::string prefix,
                                             const std::string &retained,
                                             size_t total_limit) {
  const size_t retained_storage = retained.capacity();
  if (prefix.capacity() > total_limit ||
      retained_storage > total_limit - prefix.capacity())
    throw BoundedOutputExceeded();
  const size_t input_storage = prefix.capacity() + retained_storage;
  BoundedOutputSink output((total_limit - input_storage) / 2);
  output.append(prefix);
  output.append(retained);
  return output.release();
}

#endif // BOUNDED_OUTPUT_H_INCLUDED
