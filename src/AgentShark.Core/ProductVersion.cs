using System.Reflection;

namespace AgentShark.Core;

public static class ProductVersion
{
    public static string Current => typeof(ProductVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
}
