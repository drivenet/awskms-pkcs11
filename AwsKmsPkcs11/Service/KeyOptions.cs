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

        internal IReadOnlyDictionary<string, KeyDescription> KeyDescriptions
        {
            get
            {
                if (!(_keyDescriptions is { } keyDescriptions))
                {
                    if (_keys is { } keys)
                    {
                        var newDescriptions = new Dictionary<string, KeyDescription>();
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

                            newDescriptions.Add(key, new KeyDescription(serial, value.Pin, value.Id));
                        }

                        keyDescriptions = newDescriptions;
                    }
                    else
                    {
                        keyDescriptions = EmptyKeys;
                    }

                    _keyDescriptions = keyDescriptions;
                }

                return keyDescriptions;
            }
        }
    }
}
