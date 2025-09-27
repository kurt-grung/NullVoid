// Global teardown for Jest tests
// This ensures all resources are properly cleaned up

module.exports = async () => {
  // Force garbage collection to clean up any remaining resources
  if (global.gc) {
    global.gc();
  }
  
  // Clear any remaining timers
  const activeHandles = process._getActiveHandles();
  const activeRequests = process._getActiveRequests();
  
  // Force destroy any remaining handles
  activeHandles.forEach(handle => {
    if (handle.destroy && typeof handle.destroy === 'function') {
      try {
        handle.destroy();
      } catch (e) {
        // Ignore errors during cleanup
      }
    }
  });
  
  // Clear any remaining requests
  activeRequests.forEach(request => {
    if (request.destroy && typeof request.destroy === 'function') {
      try {
        request.destroy();
      } catch (e) {
        // Ignore errors during cleanup
      }
    }
  });
  
  // Give a small delay to allow cleanup
  await new Promise(resolve => setTimeout(resolve, 100));
};
