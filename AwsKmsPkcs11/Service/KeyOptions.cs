using System.Collections.Generic;
using System.Threading;

namespace AwsKmsPkcs11.Service
{
    public sealed class KeyOptions
    {
        private static readonly IReadOnlyDictionary<string, KeyDescription> EmptyKeys = new Dictionary<string, KeyDescription>();

        private IReadOnlyDictionary<string, KeyElementOptions>? _keys;

        private IReadOnlyDictionary<string, KeyDescription>? _keyDescriptions;

        public IReadOnlyDictionary<string, KeyElementOptions>? Keys
        {
            get => _keys;
            set
            {
                _keys = value;
                Interlocked.Exchange(ref _keyDescriptions, null);
            }
        }

        internal IReadOnlyDictionary<string, KeyDescription> KeyDescriptions => _keyDescriptions ??= CreateDescriptions();

        private IReadOnlyDictionary<string, KeyDescription> CreateDescriptions()
        {
            if (!(_keys is { } keys))
            {
                return EmptyKeys;
            }

            var keyDescriptions = new Dictionary<string, KeyDescription>();
            foreach (var (key, value) in keys)
            {
                if (!KeyIdValidator.IsKeyValid(key))
                {
                    continue;
                }

                if (!(value.Serial is { } serial))
                {
                    continue;
                }

                keyDescriptions.Add(key, new KeyDescription(serial, value.Pin, value.Id));
            }

            return keyDescriptions;
        }
    }
}
