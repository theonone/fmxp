CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++20 -g

LDFLAGS = -lssl -lcrypto -lpthread -ldl

SRC_DIR  = .
BUILD_DIR = build
TARGET   = ${BUILD_DIR}/app

SRCS := $(shell find $(SRC_DIR) -name '*.cpp') $(shell find ../common -name '*.cpp')

OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -r $(BUILD_DIR) $(TARGET)

.PHONY: all clean
