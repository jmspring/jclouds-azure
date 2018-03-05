package com.innerdot.jclouds.compute;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Module;
import org.jclouds.ContextBuilder;
import org.jclouds.compute.ComputeService;
import org.jclouds.compute.ComputeServiceContext;
import org.jclouds.compute.RunNodesException;
import org.jclouds.compute.domain.NodeMetadata;
import org.jclouds.compute.domain.Template;
import org.jclouds.compute.domain.TemplateBuilder;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.scriptbuilder.domain.Statement;
import org.jclouds.scriptbuilder.statements.login.AdminAccess;
import org.jclouds.sshj.config.SshjSshClientModule;

import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.google.common.collect.Iterables.concat;
import static com.google.common.collect.Iterables.getFirst;
import static org.jclouds.compute.config.ComputeServiceProperties.TIMEOUT_SCRIPT_COMPLETE;
import static org.jclouds.compute.options.TemplateOptions.Builder.runScript;

public class App 
{
    // Provider to use
    private static final String provider = "azurecompute-arm";

    // Required properties for Azure provider
    public static final String PROPERTY_AZURE_TENANT_ID = "azurecompute-arm.tenantId";
    public static final String PROPERTY_AZURE_SUBSCRIPTION_ID = "azurecompute-arm.subscriptionId";

    public static void main( String[] args )
    {
        // Retrieve necessary config information
        if(args.length != 8) {
            System.out.println("Usage: <principal ID> <principal secret> <resouce group> <tenand ID> " +
                    "<subscription ID> <VM username> <VM Password> <SSH public key>");
            System.exit(1);
        }
        final String clientId = args[0];
        final String clientPassword = args[1];
        final String resourceGroup = args[2];
        final String tenantId = args[3];
        final String subscriptionId = args[4];
        final String vmUsername = args[5];
        final String vmPassword = args[6];
        final String sshPublicKey = args[7];

        // Set properties to be used by provider.  The azurecompute-arm provider
        // relies internally on these values being set as properties
        final ImmutableMap<String, String> azureProperties = ImmutableMap.of(
                PROPERTY_AZURE_SUBSCRIPTION_ID, subscriptionId,
                PROPERTY_AZURE_TENANT_ID, tenantId,
                TIMEOUT_SCRIPT_COMPLETE, TimeUnit.MILLISECONDS.convert(
                        Long.valueOf(System.getProperty(TIMEOUT_SCRIPT_COMPLETE, "20")), TimeUnit.MINUTES) + ""
        );
        Properties properties = new Properties();
        properties.putAll(azureProperties);

        // Modules needed for setup -- logging and so JClouds can SSH into the VM and set things up
        Iterable<Module> modules = ImmutableSet.<Module> of(
                new SshjSshClientModule(),
                new SLF4JLoggingModule()
        );

        // Generate the Compute Service.  The Compute Service takes in the configured values
        // and a template and uses the information to generate a VM.  It should be noted that
        // the code below creates a "ContextBuilder" first and retrieves the Compute Service
        // from that.  If one wants direct API access, one would use the ContextBuilder and
        // call buildApi instead of buildView.
        ComputeService compute = ContextBuilder.newBuilder(provider)
                .credentials(clientId, clientPassword)
                .modules(modules)
                .overrides(properties)
                .buildView(ComputeServiceContext.class)
                .getComputeService();

        // In order to generate the VM, we need to define the template for the VM that will
        // be created.  We also define a set of "boot instructions" that set up the a couple
        // of things in the VM
        Statement bootInstructions = AdminAccess.builder()
                .adminUsername(vmUsername)
                .adminPassword(vmPassword)
                .loginPassword(vmPassword)
                .adminPublicKey(sshPublicKey)
                .build();

        Template template = compute.templateBuilder()
                .minRam(32000)
                .minDisk(650)
                .minCores(4)
                .hardwareId("westus2/Standard_L4s")
                .options(runScript(bootInstructions))
                .build();

        // With the template, build the VM.  This can take some time.
        NodeMetadata node = null;
        Set<? extends NodeMetadata> nodes = null;
        try {
            nodes = compute.createNodesInGroup(resourceGroup, 1, template);
        } catch(RunNodesException rne) {
            System.out.println("Exception: " + rne.toString());
        }
        node = getFirst(nodes, null);

        System.out.printf("<< node %s: %s", node.getId(),
                concat(node.getPrivateAddresses(), node.getPublicAddresses()));
    }
}
