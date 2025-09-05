using Microsoft.Extensions.Caching.Memory;

namespace Auth_Api.Cache
{

    public interface ITemporarySessionStore
    {
        Task SetAsync(string sessionId, string userId, TimeSpan ttl);
        Task<string?> GetAsync(string sessionId);
        Task RemoveAsync(string sessionId);
    }
    public class MemoryTemporarySessionStore : ITemporarySessionStore
    {
        private readonly IMemoryCache _cache;

        public MemoryTemporarySessionStore(IMemoryCache cache)
        {
            _cache = cache;
        }

        public Task SetAsync(string sessionId, string userId, TimeSpan ttl)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };
            _cache.Set(GetKey(sessionId), userId, options);
            return Task.CompletedTask;
        }

        public Task<string?> GetAsync(string sessionId)
        {
            _cache.TryGetValue(GetKey(sessionId), out string? userId);
            return Task.FromResult(userId);
        }

        public Task RemoveAsync(string sessionId)
        {
            _cache.Remove(GetKey(sessionId));
            return Task.CompletedTask;
        }

        private static string GetKey(string sessionId) => $"2fa:session:{sessionId}";
    }
}
